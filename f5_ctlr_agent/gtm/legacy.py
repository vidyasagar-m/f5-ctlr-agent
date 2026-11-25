# Copyright (c) 2018-2021 F5 Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""GTM reconciliation for the standalone CIS configuration contract."""

import copy
import logging

from f5_cccl.exceptions import F5CcclError

log = logging.getLogger(__name__)

class LegacyGTMManager(object):
    """F5 Common Controller Cloud Service Management.

    The F5 Common Controller Core Library (CCCL) is an orchestration package
    that provides a declarative API for defining BIG-IP LTM and NET services
    in diverse environments (e.g. Marathon, Kubernetes, OpenStack). The
    API will allow a user to create proxy services by specifying the:
    virtual servers, pools, L7 policy and rules, monitors, arps, or fdbTunnels
    as a service description object.  Each instance of the CCCL is initialized
    with namespace qualifiers to allow it to uniquely identify the resources
    under its control.
    """

    def __init__(self, bigip, partition, user_agent=None):
        """Initialize an instance of the F5 CCCL service manager.

        :param bigip: BIG-IP management root.
        :param partition: Name of BIG-IP partition to manage.
        :param user_agent: String to append to the User-Agent header for
        iControl REST requests (default: None)
        :param prefix:  The prefix assigned to resources that should be
        managed by this CCCL instance.  This is prepended to the
        resource name (default: None)
        :param schema_path: User defined schema (default: from package)
        """
        log.debug("F5GTMManager initialize")

        # Set user-agent for ICR session
        if user_agent is not None:
            bigip.icrs.append_user_agent(user_agent)
        self._user_agent = user_agent
        self._mgmt_root = bigip
        self._partition = partition
        self._gtm_config = {}
        self._active_tenants = []
        self._deleted_tenants = []
        self._gtm = bigip.tm.gtm

    def get_gtm_config(self):
        """ Return the GTM config object"""
        return self._gtm_config

    def replace_gtm_config(self, config):
        """ Updating the GTM config object"""
        self._active_tenants = config["activeTenants"]
        self._deleted_tenants = []
        self._gtm_config = config["config"]

    def mgmt_root(self):
        """ Return the BIG-IP ManagementRoot object"""
        return self._mgmt_root

    def gtm(self):
        return self._gtm

    def get_partition(self):
        """ Return the managed partition."""
        return self._partition

    @staticmethod
    def pre_process_gtm(gtmConfig):
        for partition in gtmConfig:
            if "wideIPs" in gtmConfig[partition]:
                if gtmConfig[partition]['wideIPs'] is not None:
                    for config in gtmConfig[partition]['wideIPs']:
                        for pool in config.get('pools', []):
                            if "monitors" in pool.keys():
                                for monitor in pool['monitors']:
                                    if "send" in monitor.keys():
                                        monitor["send"] = monitor["send"].replace("\r", "\\r")
                                        monitor["send"] = monitor["send"].replace("\n", "\\n")

    def delete_update_gtm(self,partition,gtmConfig):
        """ Update GTM object in BIG-IP """
        try:
            oldConfig = self._gtm_config
            mgmt = self.mgmt_root()
            gtm=mgmt.tm.gtm
            if partition in oldConfig and partition in gtmConfig:
                opr_config = self.process_config(oldConfig[partition],gtmConfig[partition])
                rev_map = self.create_reverse_map(oldConfig[partition])
                for opr in opr_config:
                    if opr=="delete":
                        self.handle_operation_delete(gtm,partition,opr_config[opr],rev_map)
                    if opr=="create" or opr=="update":
                        self.handle_operation_create(gtm,partition,gtmConfig,opr_config[opr],opr)
        except F5CcclError as e:
            raise e

    def handle_operation_delete(self,gtm,partition,opr_config,rev_map):
        """ Handle delete operation """
        try:
            if len(opr_config["monitors"]) > 0:
                for monitor in opr_config["monitors"]:
                    poolName = rev_map["monitors"][monitor]
                    self.remove_monitor_from_gtm_pool(gtm, partition, poolName, monitor)
                    self.delete_gtm_hm(gtm, partition, monitor)

            if len(opr_config["pools"]) > 0:
                for pool in opr_config["pools"]:
                    wideipForPoolDeleted = rev_map["pools"][pool]
                    for wideip in wideipForPoolDeleted:
                        self.delete_gtm_pool(gtm, partition, wideip, pool)
            if len(opr_config["wideIPs"]) > 0:
                for wideip in opr_config["wideIPs"]:
                    self.delete_gtm_wideip(gtm, partition, wideip)
        except F5CcclError as e:
            log.error("GTM: Error while handling delete operation: %s", e)
            raise e

    def handle_operation_create(self,gtm,partition,gtmConfig,opr_config,opr):
        """ Handle create operation """
        try:
            oldConfig = copy.deepcopy(self._gtm_config)
            if len(opr_config["pools"]) > 0 or len(opr_config["monitors"]) > 0 or len(opr_config["wideIPs"]) > 0:
                if partition in gtmConfig and "wideIPs" in gtmConfig[partition]:
                    if gtmConfig[partition]['wideIPs'] is not None:
                        for config in gtmConfig[partition]['wideIPs']:
                            monitor = ""
                            newPools = dict()
                            all_monitors = ""
                            for pool in config.get('pools', []):
                                # Pool object
                                newPools[pool['name']] = {
                                    'name': pool['name'], 'partition': partition, 'ratio': 1, 'order': pool['order']
                                }
                                all_monitors = ""
                                if "monitors" in pool.keys():
                                    # Create Health Monitor
                                    for monitor in pool["monitors"]:
                                        if opr == "update" and monitor['name'] in opr_config["monitors"]:
                                            # Delete Old Health monitors
                                            self.remove_monitor_from_gtm_pool(gtm, partition, pool['name'],
                                                                              monitor['name'])
                                            self.delete_gtm_hm(gtm, partition, monitor['name'])
                                        # Create a new Health Monitor
                                        self.create_HM(gtm, partition, monitor, config['name'])
                                        all_monitors += "/" + partition + "/" + monitor['name']
                                        if monitor["name"] != pool["monitors"][-1]["name"]:
                                            all_monitors += " and "
                                # Delete the old pool members that are no longer present
                                if partition in oldConfig and "wideIPs" in oldConfig[partition] and oldConfig[partition]['wideIPs'] is not None:
                                    for oldWip in oldConfig[partition]['wideIPs']:
                                        if oldWip.get('name') == config['name']:
                                            for oldPool in oldWip.get('pools', []):
                                                if oldPool.get('name') == pool['name']:
                                                    if oldPool.get('members') is not None and pool.get('members') is not None:
                                                        oldPoolMember = set(oldPool['members'])
                                                        newPoolMember = set(pool['members'])
                                                        deleteMember = oldPoolMember - newPoolMember
                                                        for member in deleteMember:
                                                            self.remove_member_to_gtm_pool(
                                                                gtm,
                                                                partition,
                                                                oldPool['name'],
                                                                member)
                            try:
                                # Create GTM pool
                                self.create_gtm_pool(gtm, partition, config, all_monitors)
                                # Create Wideip
                                self.create_wideip(gtm, partition, config, newPools)
                            except F5CcclError as e:
                                raise e
        except F5CcclError as e:
            log.error("GTM: Error while handling create operation: %s", e)
            raise e

    def remove_unused_poolmembers(self, partition, gtmConfig):
        """Remove unused GTM PoolMembers from BIGIP created by CIS <= v2.7.1 """
        try:
            def _get_value(d, k):
                if d[k] is None:
                    return dict()
                return d[k]

            def _get_virtualNames_from_member(gtm_members):
                """ Parse GTM Virtuals from memberNames"""
                list_gtm_virtuals = {}
                for poolName in gtm_members:
                    list_gtm_virtuals[poolName] = []
                    for gtm_member in gtm_members[poolName]:
                        if '/Shared/' in gtm_member:
                            list_gtm_virtuals[poolName].append(gtm_member.split('/Shared/')[1])
                        else:
                            list_gtm_virtuals[poolName].append(gtm_member.split('/')[-1])
                return list_gtm_virtuals

            def _find_deleted_members(gtm_members,bigip_members):
                del_gtm_members = {}
                # Parse GTM Virtuals from memberNames
                list_gtm_virtuals = _get_virtualNames_from_member(gtm_members)

                # Find all deleted Members from BIGIP for respective Pool
                for poolName in gtm_members:
                    del_gtm_members[poolName] = []
                    for gtm_member in gtm_members[poolName]:
                        if "ingress_link_" not in gtm_member and poolName in bigip_members:
                            if '/Shared/' in gtm_member:
                                parts = gtm_member.split('/Shared/')
                                gtmPoolObj = parts[0]
                                gtmMemberName = parts[1]
                            else:
                                gtmPoolObj = gtm_member.rsplit('/', 1)[0]
                                gtmMemberName = gtm_member.rsplit('/', 1)[-1]
                            parseSearchStrfromMember = ('_').join(gtmMemberName.split('_')[:-1])

                            extra_bigip_members = list(set(bigip_members[poolName]) - set(list_gtm_virtuals[poolName]))
                            for bigipPoolMember in extra_bigip_members:
                                if bigipPoolMember.startswith(parseSearchStrfromMember):
                                    member = gtmPoolObj + '/Shared/' + bigipPoolMember
                                    del_gtm_members[poolName].append(member)
                return del_gtm_members

            gtm = self.gtm()
            gtm_pools = []
            for wip in _get_value(gtmConfig, "wideIPs"):
                gtm_pools += wip.get("pools", [])

            gtm_members, bigip_members = {}, {}
            # Prepare GTM members from activeConfig and bigip_members from BIGIP based on gtm_members
            for p in gtm_pools:
                if p.get("members"):
                    gtm_members[p['name']] = p["members"]
                    exist = gtm.pools.a_s.a.exists(name=p['name'], partition=partition)
                    log.debug("Pool: {}, exists: {}".format(p["name"], exist))
                    if not exist:
                        continue
                    pool = gtm.pools.a_s.a.load(name=p['name'], partition=partition)
                    bigip_members[p['name']] = [gtmMember.name for gtmMember in pool.members_s.get_collection()]

            del_gtm_members = _find_deleted_members(gtm_members,bigip_members)
            try:
                # Remove Members from BIGIP for respective GTM Pool
                for poolName in del_gtm_members:
                    for member in del_gtm_members[poolName]:
                        log.debug("GTM: Removing member:{} from Pool:{}".format(member, poolName))
                        self.remove_member_to_gtm_pool(
                            gtm,
                            partition,
                            poolName,
                            member)
            except F5CcclError as e:
                log.error("GTM: Error while removing gtm pool member: %s", e)
                raise e
        except F5CcclError as e:
            log.error("GTM: Error while processing for list of pool members to delete: %s", e)
            raise e

    def create_gtm(self, partition, gtmConfig):
        """ Create GTM object in BIG-IP """
        try:
            gtm = self.gtm()
            if "wideIPs" in gtmConfig[partition]:
                if gtmConfig[partition]['wideIPs'] is not None:
                    for config in gtmConfig[partition]['wideIPs']:
                        newPools = dict()
                        all_monitors = ""
                        for pool in config.get('pools', []):
                            # Pool object
                            newPools[pool['name']] = {
                                'name': pool['name'], 'partition': partition, 'ratio': 1, 'order': pool['order']
                            }
                            all_monitors = ""
                            if "monitors" in pool.keys():
                                for monitor in pool["monitors"]:
                                    # Create Health Monitor
                                    all_monitors += "/" + partition + "/" + monitor["name"]
                                    if monitor["name"] != pool["monitors"][-1]["name"]:
                                        all_monitors += " and "
                                    self.create_HM(gtm, partition, monitor, config['name'])
                        try:
                            # Create GTM pool
                            self.create_gtm_pool(gtm, partition, config, all_monitors)
                            # Create Wideip
                            self.create_wideip(gtm, partition, config, newPools)
                        except F5CcclError as e:
                            raise e
        except F5CcclError as e:
            log.error("GTM: Error while creating gtm: %s", e)
            raise e

    def create_wideip(self, gtm, partition, config, newPools):
        """ Create wideip and returns the wideip object """
        try:
            exist = gtm.wideips.a_s.a.exists(name=config['name'], partition=partition)
            if not exist:
                log.info('GTM: Creating wideip {}'.format(config['name']))
                gtm.wideips.a_s.a.create(
                    name=config['name'],
                    partition=partition, lastResortPool="none", poolLbMode=config['LoadBalancingMode'])
                # Attach pool to wideip
                self.attach_gtm_pool_to_wideip(gtm, config['name'], partition, list(newPools.values()))
            else:
                wideip = gtm.wideips.a_s.a.load(
                    name=config['name'],
                    partition=partition)
                if wideip.poolLbMode != config['LoadBalancingMode']:
                    wideip.poolLbMode = config['LoadBalancingMode']
                    wideip.update()
                duplicatePools = []
                if hasattr(wideip, 'pools'):
                    for p in newPools.keys():
                        if hasattr(wideip.raw['pools'], p):
                            duplicatePools.append(p)

                for poolName in duplicatePools:
                    del newPools[poolName]

                if len(newPools) > 0:
                    self.attach_gtm_pool_to_wideip(
                        gtm,
                        config['name'],
                        partition,
                        list(newPools.values()))
        except F5CcclError as e:
            log.error("GTM: Error while creating wideip: %s", e)
            raise e


    def create_gtm_pool(self, gtm, partition, config, monitors):
        """ Create gtm pools """
        try:
            for pool in config.get('pools', []):
                exist = gtm.pools.a_s.a.exists(name=pool['name'], partition=partition)
                log.debug("Pool: {}, exists: {}".format(pool["name"], exist))
                if not exist:
                    # Create pool object
                    log.info('GTM: Creating Pool: {}'.format(pool['name']))
                    pl = gtm.pools.a_s.a.create(
                        name=pool['name'],
                        partition=partition,fallbackMode=pool['fallbackMode'],loadBalancingMode=pool['LoadBalancingMode'])
                else:
                    pl = gtm.pools.a_s.a.load(
                        name=pool['name'],
                        partition=partition)
                # Updating the monitors
                if monitors != "":
                    pl.monitor = monitors
                    pl.update()
                    log.info('Updating monitors {} for pool: {}'.format(monitors, pool['name']))
                if pl.fallbackMode !=  pool['fallbackMode']:
                    pl.fallbackMode = pool['fallbackMode']
                    pl.update()
                    log.info('Updating fallbackMode {} for pool: {}'.format(pool['fallbackMode'], pool['name']))
                if pl.loadBalancingMode != pool['LoadBalancingMode']:
                    pl.loadBalancingMode = pool['LoadBalancingMode']
                    pl.update()
                    log.info('Updating loadBalancingMode {} for pool: {}'.format(pool['LoadBalancingMode'], pool['name']))
                if bool(pool['members']):
                    for member in pool['members']:
                        # Add member to pool
                        self.add_member_to_gtm_pool(
                            gtm, pl, pool['name'], member, partition)
        except F5CcclError as e:
            log.error("GTM: Error while creating pool: %s", e)
            raise e

    def attach_gtm_pool_to_wideip(self, gtm, name, partition, poolObj):
        """ Attach gtm pool to the wideip """
        #wideip.raw['pools'] =
        #[{'name': 'api-pool1', 'partition': 'test', 'order': 2, 'ratio': 1}]
        try:
            wideip = gtm.wideips.a_s.a.load(name=name, partition=partition)
            if wideip.lastResortPool == "":
                wideip.lastResortPool = "none"
            if hasattr(wideip, 'pools'):
                wideip.pools.extend(poolObj)
                log.info('GTM: Attaching Pool: {} to wideip {}'.format(poolObj, name))
                try:
                    wideip.update()
                except F5CcclError as e:
                    log.error("GTM: Error while Updating gtm pool to wideip: %s", e)
                    raise e
            else:
                wideip.raw['pools'] = poolObj
                log.info('GTM: Attaching Pool: {} to wideip {}'.format(poolObj, name))
                try:
                    wideip.update()
                except F5CcclError as e:
                    log.error("GTM: Error while Updating gtm pool to wideip: %s", e)
                    raise e
        except F5CcclError as e:
            log.error("GTM: Error while attaching gtm pool to wideip: %s", e)
            raise e

    def remove_monitor_from_gtm_pool(self,gtm,partition,poolName,monitorName):
        """ Remove monitor from gtm pool """
        try:
            pool = gtm.pools.a_s.a.load(name=poolName,partition=partition)
            if hasattr(pool,'monitor'):
                if f"/{partition}/{monitorName}" in pool.monitor:
                    monitors = pool.monitor.split(" and ")
                    monitors.remove(f"/{partition}/{monitorName}")
                    pool.monitor = " and ".join(monitors)
                    pool.update()
                    log.info("Detached health monitor {} from pool {}".format(monitorName,poolName))
        except F5CcclError as e:
            log.error("Error while removing monitor from pool: %s", e)
            raise e

    def add_member_to_gtm_pool(self, gtm, pool, poolName, memberName, partition):
        """ Add member to gtm pool """
        try:
            if not bool(pool):
                pool = gtm.pools.a_s.a.load(name=poolName,partition=partition)
            exist = pool.members_s.member.exists(
                name=memberName)
            log.debug("Pool Member: {}, exists: {}".format(memberName, exist))
            if not exist:
                s = memberName.split(":")
                server = s[0].split("/")[-1]
                vs_name = s[1] if len(s) > 1 else ""
                serverExist = gtm.servers.server.exists(name=server)
                log.debug("Server: {}, exists: {}".format(server, serverExist))
                if serverExist:
                    sl = gtm.servers.server.load(name=server)
                    vsExist = sl.virtual_servers_s.virtual_server.exists(
                        name=vs_name)
                    log.debug("Virtual Server: {}, exists: {}".format(vs_name, vsExist))
                    if vsExist:
                        pmExist=pool.members_s.member.exists(
                            name=memberName,
                            partition="Common")
                        log.debug("Pool Member: {}, exists: {}".format(memberName, pmExist))
                        if not pmExist:
                            #Add member to gtm pool created
                            log.info('GTM: Adding pool member {} to pool {}'.format(
                                memberName,poolName))
                            pool.members_s.member.create(
                                name = memberName,
                                partition = "Common")
                    else:
                        raise F5CcclError(
                            msg="Virtual Server Resource not Available in BIG-IP")
                else:
                    # Delete pool for invalid server config
                    pool = gtm.pools.a_s.a.load(name=poolName, partition=partition)
                    pool.delete()
                    raise F5CcclError(msg="Server Resource not Available in BIG-IP")
        except (F5CcclError) as e:
            log.debug("GTM: Error while adding member to pool.")
            raise e


    def get_bigip_version(self):
        try:
            mgmt= self.mgmt_root()
            verList = mgmt.tmos_version.split('.')
            return float(verList[0] + '.' + verList[1])
        except F5CcclError as e:
            log.error("GTM: Could not fetch BigipVersion: %s", e)
            raise e

    def create_HM(self, gtm, partition, monitor, wideIPName):
        """ Create Health Monitor """
        try:
            if bool(monitor):
                if monitor['type'] == "http":
                    exist = gtm.monitor.https.http.exists(
                        name=monitor['name'],
                        partition=partition)
                if monitor['type'] == "https":
                    exist = gtm.monitor.https_s.https.exists(
                        name=monitor['name'],
                        partition=partition)
                if monitor['type'] == "tcp":
                    exist = gtm.monitor.tcps.tcp.exists(
                        name=monitor['name'],
                        partition=partition)
                if not exist:
                    if monitor['type'] == "http":
                        try:
                            gtm.monitor.https.http.create(
                                name=monitor['name'],
                                partition=partition,
                                send=monitor['send'],
                                recv=monitor['recv'],
                                interval=monitor['interval'],
                                timeout=monitor['timeout'])
                        except F5CcclError as e:
                           log.debug("GTM: Error while creating http Health Monitor: %s", e)
                           raise e
                    if monitor['type'] == "https":
                        try:
                            if self.get_bigip_version() >= 16.1:
                                gtm.monitor.https_s.https.create(
                                    name=monitor['name'],
                                    partition=partition,
                                    send=monitor['send'],
                                    recv=monitor['recv'],
                                    sniServerName=wideIPName,
                                    interval=monitor['interval'],
                                    timeout=monitor['timeout'])
                            else:
                                gtm.monitor.https_s.https.create(
                                    name=monitor['name'],
                                    partition=partition,
                                    send=monitor['send'],
                                    recv=monitor['recv'],
                                    interval=monitor['interval'],
                                    timeout=monitor['timeout'])
                        except F5CcclError as e:
                           log.debug("GTM: Error while creating https Health Monitor: %s", e)
                           raise e
                    if monitor['type'] == "tcp":
                        try:
                            gtm.monitor.tcps.tcp.create(
                                name=monitor['name'],
                                partition=partition,
                                interval=monitor['interval'],
                                timeout=monitor['timeout'])
                        except F5CcclError as e:
                           log.debug("GTM: Error while creating tcp Health Monitor: %s", e)
                           raise e
                else:
                    try:
                        if monitor['type'] == "http":
                            obj = gtm.monitor.https.http.load(
                                name=monitor['name'],
                                partition=partition)
                            obj.send = monitor['send']
                            obj.interval = monitor['interval']
                            obj.timeout = monitor['timeout']
                            obj.update()
                            log.info("HTTP Health monitor {} updated.".format(monitor['name']))
                        if monitor['type'] == "https":
                            log.info("HTTPS Health monitor %s updating.", monitor['name'])
                            obj = gtm.monitor.https_s.https.load(
                                name=monitor['name'],
                                partition=partition)
                            obj.send = monitor['send']
                            obj.interval = monitor['interval']
                            obj.timeout = monitor['timeout']
                            if self.get_bigip_version() >= 16.1:
                                obj.sniServerName = wideIPName
                            obj.update()
                            log.info("HTTPS Health monitor {} updated.".format(monitor['name']))
                        if monitor['type'] == "tcp":
                            log.info("TCP Health monitor %s updating.", monitor['name'])
                            obj = gtm.monitor.tcps.tcp.load(
                                name=monitor['name'],
                                partition=partition)
                            obj.interval = monitor['interval']
                            obj.timeout = monitor['timeout']
                            obj.update()
                    except F5CcclError as e:
                        log.debug("GTM: Error while Updating Health Monitor: %s", e)
                        raise e
        except F5CcclError as e:
            log.debug("GTM: Error while creating Health Monitor: %s", e)
            raise e


    def remove_member_to_gtm_pool(self,gtm,partition,poolName,memberName):
        """ Remove member to gtm pool """
        try:
            parts = memberName.split(":")
            if len(parts) > 1 and "/" in parts[1]:
                tenant_parts = parts[1].split("/")
                if len(tenant_parts) > 1:
                    tenant = tenant_parts[1]
                    if tenant not in self._active_tenants + self._deleted_tenants:
                        log.debug("GTM: Not removing the pool member %s as it may not be created by this CIS instance", memberName)
                        return
            exist=gtm.pools.a_s.a.exists(name=poolName, partition=partition)
            if exist:
                pool = gtm.pools.a_s.a.load(name=poolName,partition=partition)
                memObj = pool.members_s.member.load(name=memberName)
                memObj.delete()
                log.info("Member {} deleted.".format(memberName))
        except F5CcclError as e:
            log.error("GTM: Error while removing pool member: %s", e)
            raise e

    def remove_gtm_pool_to_wideip(self, gtm, wideipName, partition, poolName):
        """ Remove gtm pool to the wideip """
        try:
            wideip = gtm.wideips.a_s.a.load(name=wideipName,partition=partition)
            if wideip.lastResortPool == "":
                wideip.lastResortPool = "none"
            if hasattr(wideip,'pools'):
                for pool in wideip.pools:
                    if pool["name"]==poolName:
                        wideip.pools.remove(pool)
                        wideip.update()
                        log.info("Removed the pool: {}".format(poolName))
        except F5CcclError as e:
            log.error("GTM: Error while removing pool: %s", e)
            raise e

    def delete_gtm_pool(self,gtm,partition,wideipName,poolName):
        """ Delete gtm pools """
        try:
            oldConfig = copy.deepcopy(self._gtm_config)
            if partition in oldConfig and oldConfig[partition].get('wideIPs') is not None:
                for wideip in oldConfig[partition]['wideIPs']:
                    if wideipName == wideip.get('name'):
                        for pool in wideip.get('pools', []):
                            if pool.get('name') == poolName and pool.get('members') is not None:
                                for member in pool['members']:
                                    self.remove_member_to_gtm_pool(
                                        gtm,
                                        partition,
                                        poolName,
                                        member)
                                break
                        break
            if gtm.pools.a_s.a.exists(name=poolName, partition=partition):
                obj = gtm.pools.a_s.a.load(
                    name=poolName,
                    partition=partition)
                # delete the gtm pool and remove the pool from wide ip once there are no pool members attached to it.
                if len(obj.members_s.get_collection()) == 0:
                    self.remove_gtm_pool_to_wideip(gtm,
                        wideipName,partition,poolName)
                    obj.delete()
                    log.info("Deleted the pool: {}".format(poolName))
                    if partition in self._gtm_config and self._gtm_config[partition].get('wideIPs') is not None:
                        for wideip in self._gtm_config[partition]['wideIPs']:
                            if wideip.get('name') == wideipName:
                                wideip['pools'] = [p for p in wideip.get('pools', []) if p.get('name') != poolName]
                                break
        except F5CcclError as e:
            log.error("GTM: Error while deleting pool: %s", e)
            raise e


    def delete_gtm_wideip(self,gtm,partition,wideipName):
        """ Delete gtm wideip """
        try:
            if gtm.wideips.a_s.a.exists(name=wideipName, partition=partition):
                wideip = gtm.wideips.a_s.a.load(
                        name=wideipName,
                        partition=partition)
                if wideip.lastResortPool == "":
                    wideip.lastResortPool = "none"
                if hasattr(wideip,'pools') and len(wideip.pools) > 0:
                    log.info("Could not delete wideip as pool object exist.")
                else:
                    wideip.delete()
                    log.info("Deleted the wideIP: {}".format(wideipName))
                    if partition in self._gtm_config and self._gtm_config[partition].get('wideIPs') is not None:
                        self._gtm_config[partition]['wideIPs'] = [w for w in self._gtm_config[partition]['wideIPs'] if w.get('name') != wideipName]
        except F5CcclError as e:
            log.error("Could not delete wideip: %s", e)
            raise e

    def delete_gtm_hm_helper(self, partition, monitorName):
        oldConfig = copy.deepcopy(self._gtm_config)
        if partition in oldConfig and oldConfig[partition].get('wideIPs') is not None:
            for config in oldConfig[partition]['wideIPs']:
                for pool in config.get('pools', []):
                    if "monitors" in pool.keys():
                        for monitor in pool.get('monitors', []):
                            if monitorName == monitor.get('name'):
                                return monitor.get('type')
        return None

    def delete_gtm_hm(self,gtm,partition,monitorName):
        """ Delete gtm health monitor """
        try:
            mon_type = self.delete_gtm_hm_helper(partition, monitorName)
            if mon_type == "http":
                if gtm.monitor.https.http.exists(name=monitorName, partition=partition):
                    obj = gtm.monitor.https.http.load(
                                name=monitorName,
                                partition=partition)
                    obj.delete()
                    log.info("Deleted the HTTP Health monitor: {}".format(monitorName))
            elif mon_type == "https":
                if gtm.monitor.https_s.https.exists(name=monitorName, partition=partition):
                    obj = gtm.monitor.https_s.https.load(
                                name=monitorName,
                                partition=partition)
                    obj.delete()
                    log.info("Deleted the HTTPS Health monitor: {}".format(monitorName))
            elif mon_type == "tcp":
                if gtm.monitor.tcps.tcp.exists(name=monitorName, partition=partition):
                    obj = gtm.monitor.tcps.tcp.load(
                                name=monitorName,
                                partition=partition)
                    obj.delete()
                    log.info("Deleted the TCP Health monitor: {}".format(monitorName))
            if partition in self._gtm_config and self._gtm_config[partition].get('wideIPs') is not None:
                for config in self._gtm_config[partition]['wideIPs']:
                    for pool in config.get('pools', []):
                        if "monitors" in pool:
                            pool["monitors"] = [m for m in pool["monitors"] if m.get("name") != monitorName]
        except F5CcclError as e:
            log.error("GTM: Could not delete health monitor: %s", e)
            raise e

    def process_config(self, d1, d2):
        """ Process old and new config """
        def _get_resource_from_list(lst, rsc_name):
            for rsc in lst:
                if rsc["name"] == rsc_name:
                    return rsc

        def _are_wip_equal(wip1, wip2):
            if wip1["recordType"] != wip2["recordType"]:
                return False
            if wip1["loadBalancingMode"] != wip2["loadBalancingMode"]:
                return False

            pool_set1 = set([p["name"] for p in wip1["pools"]])
            pool_set2 = set([p["name"] for p in wip2["pools"]])

            new_pools = pool_set2 - pool_set1
            del_pools = pool_set1 - pool_set2

            if len(new_pools) or len(del_pools):
                return False

            return True

        def _are_pools_equal(pool1, pool2):
            if pool1["recordType"] != pool2["recordType"]:
                return False
            if pool1["loadBalancingMode"] != pool2["loadBalancingMode"]:
                return False

            mem_set1 = set(pool1["members"])
            mem_set2 = set(pool2["members"])

            if len(mem_set1) or len(mem_set2):
                return False

            if pool1["monitor"]["name"] != pool2["monitor"]["name"]:
                return False

            return True

        def _get_crud_wide_ips(d1, d2):
            wip_set1 = set([v["name"] for v in _get_value(d1,"wideIPs")])
            wip_set2 = set([v["name"] for v in _get_value(d2,"wideIPs")])

            del_wips = list(wip_set1 - wip_set2)
            new_wips = list(wip_set2 - wip_set1)
            cur_wips = wip_set1.intersection(wip_set2)
            update_wips = []

            for wip_name in cur_wips:
                wip1 = _get_resource_from_list(_get_value(d1,"wideIPs"), wip_name)
                wip2 = _get_resource_from_list(_get_value(d2,"wideIPs"), wip_name)

                if wip1 != wip2:
                    update_wips.append(wip_name)

            return new_wips, del_wips, update_wips

        def _get_crud_pools(d1, d2):
            pools1 = []
            pools2 = []
            for wip in _get_value(d1,"wideIPs"):
                pools1 += wip.get("pools", [])
            for wip in _get_value(d2,"wideIPs"):
                pools2 += wip.get("pools", [])

            pool_set1 = set([p["name"] for p in pools1])
            pool_set2 = set([p["name"] for p in pools2])

            new_pools = list(pool_set2 - pool_set1)
            del_pools = list(pool_set1 - pool_set2)
            cur_pools = pool_set1.intersection(pool_set2)
            update_pools = []

            for pool_name in cur_pools:
                pool1 = _get_resource_from_list(pools1, pool_name)
                pool2 = _get_resource_from_list(pools2, pool_name)

                if pool1 != pool2:
                    update_pools.append(pool_name)

            return new_pools, del_pools, update_pools

        def _get_value(d,k):
            if d[k] is None:
                return dict()
            return d[k]

        def _get_crud_monitors(d1, d2):
            pools1 = []
            pools2 = []
            for wip in _get_value(d1,"wideIPs"):
                pools1 += wip.get("pools", [])
            for wip in _get_value(d2,"wideIPs"):
                pools2 += wip.get("pools", [])

            monitors1, monitors2 = [], []
            for p in pools1:
                if p.get("monitors"):
                    monitors1 += p["monitors"]
            for p in pools2:
                if p.get("monitors"):
                    monitors2 += p["monitors"]

            mon_set1 = set([m["name"] for m in monitors1])
            mon_set2 = set([m["name"] for m in monitors2])

            new_mons = list(mon_set2 - mon_set1)
            del_mons = list(mon_set1 - mon_set2)
            cur_mons = mon_set1.intersection(mon_set2)
            update_mons = []

            for mon_name in cur_mons:
                mon1 = _get_resource_from_list(monitors1, mon_name)
                mon2 = _get_resource_from_list(monitors2, mon_name)

                if mon1 != mon2:
                    update_mons.append(mon_name)

            return new_mons, del_mons, update_mons

        new_wips, del_wips, update_wips = _get_crud_wide_ips(d1, d2)

        new_pools, del_pools, update_pools = _get_crud_pools(d1, d2)

        new_mons, del_mons, update_mons = _get_crud_monitors(d1, d2)

        return {
            "create": {
                "wideIPs": new_wips,
                "pools": new_pools,
                "monitors": new_mons
            },
            "delete": {
                "wideIPs": del_wips,
                "pools": del_pools,
                "monitors": del_mons
            },
            "update": {
                "wideIPs": update_wips,
                "pools": update_pools,
                "monitors": update_mons
            }
        }

    def create_reverse_map(self,d):
        rev_map = dict()
        rev_map["pools"] = dict()
        rev_map["monitors"] = dict()
        if d["wideIPs"] is None:
            di = dict()
        else:
            di = d["wideIPs"]
        for wip in di:
            wip_name = wip["name"]
            for pool in wip.get("pools", []):
                pool_name = pool["name"]
                try:
                    rev_map["pools"][pool_name].append(wip_name)
                except:
                    rev_map["pools"][pool_name] = [wip_name]

                try:
                    for monitor in pool["monitors"]:
                        rev_map["monitors"][monitor["name"]] = pool_name
                except:
                    pass
        return rev_map
