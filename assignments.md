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
| Trust Anchor ID | Subject                                                 | crt.sh CA ID link            |
|-----------------|---------------------------------------------------------|------------------------------|
| 11129.9.1       | CN=GTS Root R1,O=Google Trust Services LLC,C=US         | https://crt.sh/?caid=48269   |
| 11129.9.2       | CN=GTS Root R2,O=Google Trust Services LLC,C=US         | https://crt.sh/?caid=48271   |
| 11129.9.3       | CN=GTS Root R3,O=Google Trust Services LLC,C=US         | https://crt.sh/?caid=48268   |
| 11129.9.4       | CN=GTS Root R4,O=Google Trust Services LLC,C=US         | https://crt.sh/?caid=48274   |
| 11129.9.5       | CN=WR1,O=Google Trust Services,C=US                     | https://crt.sh/?caid=286242  |
| 11129.9.6       | CN=WR2,O=Google Trust Services,C=US                     | https://crt.sh/?caid=286243  |
| 11129.9.7       | CN=WR3,O=Google Trust Services,C=US                     | https://crt.sh/?caid=286244  |
| 11129.9.8       | CN=WR4,O=Google Trust Services,C=US                     | https://crt.sh/?caid=286245  |
| 11129.9.9       | CN=WR5,O=Google Trust Services,C=US                     | https://crt.sh/?caid=286246  |
| 11129.9.10      | CN=WE1,O=Google Trust Services,C=US                     | https://crt.sh/?caid=286236  |
| 11129.9.11      | CN=WE2,O=Google Trust Services,C=US                     | https://crt.sh/?caid=286237  |
| 11129.9.12      | CN=WE3,O=Google Trust Services,C=US                     | https://crt.sh/?caid=286239  |
| 11129.9.13      | CN=WE4,O=Google Trust Services,C=US                     | https://crt.sh/?caid=286240  |
| 11129.9.14      | CN=WE5,O=Google Trust Services,C=US                     | https://crt.sh/?caid=286241  |
| 11129.9.15      | CN=AE1,O=Google Trust Services,C=US                     | https://crt.sh/?caid=286234  |
| 44947.2.1       | CN=ISRG Root X1,O=Internet Security Research Group,C=US | https://crt.sh/?caid=7394    |
| 44947.2.2       | CN=Let's Encrypt Authority X1,O=Let's Encrypt,C=US      | https://crt.sh/?caid=7395    |
| 44947.2.3       | CN=Let's Encrypt Authority X2,O=Let's Encrypt,C=US      | https://crt.sh/?caid=9745    |
| 44947.2.4       | CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US      | https://crt.sh/?caid=16418   |
| 44947.2.5       | CN=Let's Encrypt Authority X4,O=Let's Encrypt,C=US      | https://crt.sh/?caid=16429   |
| 44947.2.6       | CN=ISRG Root X2,O=Internet Security Research Group,C=US | https://crt.sh/?caid=183269  |
| 44947.2.7       | CN=E1,O=Let's Encrypt,C=US                              | https://crt.sh/?caid=183283  |
| 44947.2.8       | CN=E2,O=Let's Encrypt,C=US                              | https://crt.sh/?caid=183284  |
| 44947.2.9       | CN=R3,O=Let's Encrypt,C=US                              | https://crt.sh/?caid=183267  |
| 44947.2.10      | CN=R4,O=Let's Encrypt,C=US                              | https://crt.sh/?caid=183268  |
| 44947.2.11      | CN=E5,O=Let's Encrypt,C=US                              | https://crt.sh/?caid=295810  |
| 44947.2.12      | CN=E6,O=Let's Encrypt,C=US                              | https://crt.sh/?caid=295819  |
| 44947.2.13      | CN=E7,O=Let's Encrypt,C=US                              | https://crt.sh/?caid=295813  |
| 44947.2.14      | CN=E8,O=Let's Encrypt,C=US                              | https://crt.sh/?caid=295809  |
| 44947.2.15      | CN=E9,O=Let's Encrypt,C=US                              | https://crt.sh/?caid=295812  |
| 44947.2.16      | CN=R10,O=Let's Encrypt,C=US                             | https://crt.sh/?caid=295814  |
| 44947.2.17      | CN=R11,O=Let's Encrypt,C=US                             | https://crt.sh/?caid=295815  |
| 44947.2.18      | CN=R12,O=Let's Encrypt,C=US                             | https://crt.sh/?caid=295816  |
| 44947.2.19      | CN=R13,O=Let's Encrypt,C=US                             | https://crt.sh/?caid=295817  |
| 44947.2.20      | CN=R14,O=Let's Encrypt,C=US                             | https://crt.sh/?caid=295818  |
| 44947.2.21      | CN=Root YE,O=ISRG,C=US                                  | https://crt.sh/?caid=430535  |
| 44947.2.22      | CN=Root YR,O=ISRG,C=US                                  | https://crt.sh/?caid=430543  |
| 44947.2.23      | CN=YE1,O=Let's Encrypt,C=US                             | https://crt.sh/?caid=432952  |
| 44947.2.24      | CN=YE2,O=Let's Encrypt,C=US                             | https://crt.sh/?caid=431054  |
| 44947.2.25      | CN=YE3,O=Let's Encrypt,C=US                             | https://crt.sh/?caid=432914  |
| 44947.2.26      | CN=YR1,O=Let's Encrypt,C=US                             | https://crt.sh/?caid=432476  |
| 44947.2.27      | CN=YR2,O=Let's Encrypt,C=US                             | https://crt.sh/?caid=432477  |
| 44947.2.28      | CN=YR3,O=Let's Encrypt,C=US                             | https://crt.sh/?caid=432480  |
