# f5-ctlr-agent
A python agent for bridging between F5 BIG-IP controllers and F5 CCCL.

# Installation
Add f5-ctlr-agent to the `requirements.txt` file for your project. Use [editable package format] (https://pip.readthedocs.io/en/stable/reference/pip_install/#git):
```
[-e] git+https://git.myproject.org/MyProject#egg=MyProject
```
To install in your project run `pip install --process-dependency-links -r requirements.txt`.

## CIS and GTM compatibility

The agent accepts both the CIS 2.20 GTM payload and the `rel-k8s-2.4.x`
GTM payload. CIS 2.20 payloads use the existing-server GTM reconciler;
release 2.4 payloads (including its non-BNK path) carry `clusterIdentifier`,
`digitalAssetID` and `enableDataServerMonitor` and use the
infrastructure-managing reconciler, even when those values are empty or false.
A running worker rejects a change between these payload contracts rather
than applying one contract to objects managed by the other.

The runtime and build requirements pin the integrated CCCL revision in the
`vidyasagar-m` fork. Install that requirements file when installing the agent
independently. Package metadata declares `f5-cccl` by name so CIS image builds
can install the separately staged CCCL source without fetching Git during
installation. The CIS image's own agent and CCCL source pins must be updated
after the integration branches are committed and published; changing this
repository alone does not update either CIS image.

# Filing Issues

When filing issues please provide:

* Clear steps on how to replicate the issue
* Stack trace and error messages
* SHA and branch information for f5-ctlr-agent
* SHA and branch information for F5 BIG-IP controller component
* SHA and branch information for F5 CCCL component

# Contributing

This project is used internally by other F5 projects; we're not yet ready to accept contributions. Please check back later or see if another project, such as https://github.com/F5Networks/f5-common-python would be a good place for your contribution.

# Copyright

Copyright (c) 2018-2021 F5 Networks, Inc.

# License

## Apache V2.0

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations
under the License.
