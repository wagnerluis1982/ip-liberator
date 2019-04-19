=====
Usage
=====

TODO: replace quickstart with a well detailed usage.

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
