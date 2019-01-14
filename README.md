# NextGIS installer synchronizer

NextGIS installer synchronizer is tool to synchronize NextGIS official network
installer repository and repository in closed network (for example, corporate,
enterprise, government local networks, etc.). Also this tool forms special
license key for unlimited users of paid software features.

The tool is python script. The tool input parameters are:

* remote repository URL
* NextGIS account login and password

The output parameter is path to local repository folder.

It is expected that NextGIS installer executable with modified repository URL is
available in closed network for corporate/enterprise/government users.

# Requirements

Tool has following requirements:

* requests
* tqdm
* subprocess
* shutil
* hashlib
* xml.etree
* json

# Install

The tool tested on **Ubuntu 16.04 LTS** or higher. To install tool clone it to
*/opt/nextgis_installer_sync* using following commands:

> cd /opt
> git clone https://github.com/nextgis/nextgis_installer_sync.git

# Use example

For synchronize NextGIS installer for Windows 64 bit repository execute the
following command:

> python repo_sync.py -i http://nextgis.com/programs/desktop/repository-win64 -u {nextgis_user} -p {nextgis_user_password} -o /usr/share/nginx/repos/repository-win64

# License

All scripts are licensed under GNU GPL v.2.
[![License](https://img.shields.io/badge/License-GPL%20v2-blue.svg?maxAge=2592000)]()

# Commercial support

Need to fix a bug or add a feature to NextGIS installer synchronizer? We provide
custom development and support for this software.
[Contact us](http://nextgis.ru/en/contact/) to discuss options!

[![http://nextgis.com](http://nextgis.ru/img/nextgis.png)](http://nextgis.com)
