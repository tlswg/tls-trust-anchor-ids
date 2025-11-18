# Trust Anchor Identifier Assignments

To facilitate early experiments with Trust Anchor Identifiers, the following table tracks the list of allocated trust anchor IDs. This table tracks the current OID-based allocation scheme. The final standard may ultimately use a different mechanism.

## Steps to assign new IDs:
1. If needed, obtain a Private Enterprise Number OID from IANA ([Request Form](https://www.iana.org/assignments/enterprise-numbers/assignment/apply/))
2. For each participating trust anchor, identified by their {Subject, Public Key} tuple, assign a unique OID under the PEN. Assignments can be spot checked against crt.sh, which assigns unique CA IDs using the same fields.
3. Submit a pull request that adds a new row to the below table for each trust anchor ID assignment.

### Notes:
* Trust Anchor IDs should use the ASCII (dotted decimal) notation, e.g. `32473.1`.
* Subject and Public Key information for each CA can be obtained from the crt.sh CA ID links
* The Subject column in this table is intended for human readability only.


## List of assigned IDs
| Trust Anchor ID | Subject                                         | Trust Anchor by crt.sh CA ID link |
|-----------------|-------------------------------------------------|------------------------------|
| 11129.9.1       | CN=GTS Root R1,O=Google Trust Services LLC,C=US | https://crt.sh/?caid=48269   |
| 11129.9.2       | CN=GTS Root R2,O=Google Trust Services LLC,C=US | https://crt.sh/?caid=48271   |
| 11129.9.3       | CN=GTS Root R3,O=Google Trust Services LLC,C=US | https://crt.sh/?caid=48268   |
| 11129.9.4       | CN=GTS Root R4,O=Google Trust Services LLC,C=US | https://crt.sh/?caid=48274   |
| 11129.9.5       | CN=WR1,O=Google Trust Services,C=US             | https://crt.sh/?caid=286242  |
| 11129.9.6       | CN=WR2,O=Google Trust Services,C=US             | https://crt.sh/?caid=286243  |
| 11129.9.7       | CN=WR3,O=Google Trust Services,C=US             | https://crt.sh/?caid=286244  |
| 11129.9.8       | CN=WR4,O=Google Trust Services,C=US             | https://crt.sh/?caid=286245  |
| 11129.9.9       | CN=WR5,O=Google Trust Services,C=US             | https://crt.sh/?caid=286246  |
| 11129.9.10      | CN=WE1,O=Google Trust Services,C=US             | https://crt.sh/?caid=286236  |
| 11129.9.11      | CN=WE2,O=Google Trust Services,C=US             | https://crt.sh/?caid=286237  |
| 11129.9.12      | CN=WE3,O=Google Trust Services,C=US             | https://crt.sh/?caid=286239  |
| 11129.9.13      | CN=WE4,O=Google Trust Services,C=US             | https://crt.sh/?caid=286240  |
| 11129.9.14      | CN=WE5,O=Google Trust Services,C=US             | https://crt.sh/?caid=286241  |
| 11129.9.15      | CN=AE1,O=Google Trust Services,C=US             | https://crt.sh/?caid=286234  |
