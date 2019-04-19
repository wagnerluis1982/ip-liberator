============
IP Liberator
============


.. image:: https://img.shields.io/pypi/v/ip-liberator.svg
        :target: https://pypi.python.org/pypi/ip-liberator

.. image:: https://img.shields.io/travis/wagnerluis1982/ip-liberator.svg
        :target: https://travis-ci.org/wagnerluis1982/ip-liberator

.. image:: https://readthedocs.org/projects/ip-liberator/badge/?version=latest
        :target: https://ip-liberator.readthedocs.io/en/latest/?badge=latest
        :alt: Documentation Status


A command line utility to update AWS Security Groups rules.


* Free software: GNU General Public License v3
* Documentation: https://ip-liberator.readthedocs.io.


Features
--------

* Update a list of security groups of your AWS account at once.
* Grant access to informed ports for your current IP address or an informed IP.
* Read profile files in JSON with all the information needed to contact.
* Fit for use as script (e.g. to update your dynamic IP regularly).

Installation
------------

.. code-block:: console

    $ pip install ip-liberator

Quickstart
----------

Consider a file ``/path/my-profile.json`` with the following content:

.. code-block:: json

    {
      "credentials": {
        "access_key": "<AWS_ACCESS_KEY>",
        "secret_key": "<AWS_SECRET_KEY>",
        "region_name": "<AWS REGION>"
      },
      "config": {
        "operator": "John",
        "services": [
          {
            "name": "FTP+SFTP",
            "port": "21-22"
          },
          {
            "name": "HTTPS",
            "port": "443"
          }
        ],
        "security_groups": [
          "sg-<GROUP_ID_1>",
          "sg-<GROUP_ID_2>"
        ]
      }
    }

Using the profile defined above will create or update two entries in the informed security groups:

- **John FTP+SFTP** granting access for the current IP the ports 21 and 22.
- **John HTTPS** granting access for the current IP the port 443.

To accomplish it, simply run:

.. code-block:: console

    $ ip-liberator --profile /path/my-profile.json
    Authorizing rules ['John FTP+SSH', 'John HTTPS'] to IP 192.30.253.112/32
    - sg-<GROUP_ID_1>
    - sg-<GROUP_ID_2>

Credits
-------

Authors
:::::::

* Wagner Macedo <wagnerluis1982@gmail.com> (maintainer)
