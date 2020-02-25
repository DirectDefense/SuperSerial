# SuperSerial
SuperSerial - Burp Java Deserialization Vulnerability Identification 

See Blog: https://www.directdefense.com/superserial-java-deserialization-burp-extension/
See Active Identification Burp Extender: https://github.com/DirectDefense/SuperSerial-Active

To help our customers and readers identify or locate Java Deserialization issues, we have created a Burp Suite Extender called “SuperSerial” (South Park reference of Al Gore). This Burp Extender will help you locate all client requests and server responses containing plaintext Java serialized objects. Additionally, the Extender will help locate server responses containing base64-encoded Java serialized objects. Requests containing base64-encoded Java serialized objects are not detected by this Extender, as Burp Suite reports these natively using the "Serialized object in HTTP message" scan issue. Any of these conditions will likely indicate a Java Deserialization issue, but the only way your team can identify all deserialization issues is from a code review perspective.
 
 
## Usage
 
1. Download the latest jar file
 
2. Once downloaded, load the extender Jar in the Extender tab (requires Java Runtime Environment 7 or higher).

3. Next, turn on Passive Scanning in the scanner tab and spider your application environments. You may want to constrain it to “Suite Scope” to avoid scanning other party’s applications, but make sure you set the scope in the Target tab appropriately.

4. Since serialized data will appear as binary in Burp, make sure to change your filters in the proxy history and target tab to show “Other Binary”.

5. Finally, spider your application’s environment and manually walk through all interfaces. If anything was discovered, it will appear in the scanner tab.

Extender written by Jeff Cap


## COPYRIGHT

SuperSerial-Passive
Created by Jeff Cap
Copyright (C) 2015 DirectDefense, Inc.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see http://www.gnu.org/licenses/
