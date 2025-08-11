
SOC Analyst Johny has observed some anomalous behaviours in the logs of a few windows machines. It looks like the adversary has access to some of these machines and successfully created some backdoor. His manager has asked him to pull those logs from suspected hosts and ingest them into Splunk for quick investigation. Our task as SOC Analyst is to examine the logs and identify the anomalies.

Task 1: How many events were collected and Ingested in the index main?
Go to search - > New search type: index="main" .

Answer: `12256 events.`

   ![Screenshot](Document_Images/image1.png)



---
Task 2: On one of the infected hosts, the adversary was successful in creating a backdoor user. What is the new username?

The Windows event ID for creating a user account is 4720. Add on to the search bar and you will see only got 1 creating user event. 

Answer: A1berto

   ![Screenshot](Document_Images/image2.png)



----
Task 3: On the same host, a registry key was also updated regarding the new backdoor user. What is the full path of that registry key?

Go to back to : index="main" – > select : Category="Registry object added or deleted (rule: RegistryEvent)"


   ![Screenshot](Document_Images/image3.png)

Add the “A1berto” to search bar. Will show 2 events. One of the EventType: Deletekey. 
The full path of registry key:
Answer : HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto
 

   ![Screenshot](Document_Images/image4.png)



---
Task 4: Examine the logs and identify the user that the adversary was trying to impersonate.

Go to the main page of user. I see one of the user call Alberto .The adversary is trying to impersonate to Alberto so creating a user call A1berto.

   ![Screenshot](Document_Images/image5.png)



----
Task 5: What is the command used to add a backdoor user from a remote computer?
When I investigate to the user :James . I saw a some weird comandline.

"C:\windows\System32\Wbem\WMIC.exe" /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1"

What this command does:
This command uses WMIC (Windows Management Instrumentation Command-line) to remotely create a new user account on a Windows system.

•	WMIC.exe: A command-line utility that allows interaction with WMI to manage local or remote systems.
•	/node:WORKSTATION6: Specifies the target computer (WORKSTATION6) where the command will run.
•	process call create "net user /add A1berto paw0rd1": Remotely runs the command to create a new user:
•	Username: A1berto
•	Password: paw0rd1

 Purpose and Use Case:
This technique is commonly used for:
•	Lateral movement in a network.
•	Remote account creation by administrators — or attackers.
•	Persistence, allowing continued access via a new user account.

 Why it's suspicious in threat detection:
•	WMIC is often abused by attackers for stealthy remote execution.
•	Account creation with a weak or default-style password can be a red flag.
•	Seen in post-exploitation stages of many attacks.

 Summary:
A new user account named A1berto was created remotely on WORKSTATION6 using WMIC, a technique often used for lateral movement or unauthorized persistence.


Answer : "C:\windows\System32\Wbem\WMIC.exe" /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1"

   ![Screenshot](Document_Images/image6.png)



---
Task 6: How many times was the login attempt from the backdoor user observed during the investigation?
Go to the main page search bar : index="main" A1berto 
For the category I didn’t see any login attempt categaory.

   ![Screenshot](Document_Images/image7.png)

The event id only 8 values. I didn’t see any related to login attempt event id

Event ID 4625: This event is triggered every time a user or system attempts to log in but fails. 
Event ID 4624:This event is logged when a logon attempt is successful.

Answer: 0

   ![Screenshot](Document_Images/image8.png)



---
Task 7: What is the name of the infected host on which suspicious Powershell commands were executed?

Based on the task 5, we know is James.

Hostname : James.browne (Answer) 

   ![Screenshot](Document_Images/image9.png)



----
Task 8: PowerShell logging is enabled on this device. How many events were logged for the malicious PowerShell execution?

Go to search bar : index="main" powershell
Then click the event id. You will see the 9 values of Event ID. 
The Event ID 4103 is for logged within the Microsoft-Windows-PowerShell/Operational event log, indicates the execution of PowerShell commands and cmdlets. 

The Event ID 4103 got 79 count events .

Answer :79

   ![Screenshot](Document_Images/image10.png)



---
Task 9: An encoded Powershell script from the infected host initiated a web request. What is the full URL?
Go to search bar : index="main" powershell

I saw an encoded Powershell script 

   ![Screenshot](Document_Images/image11.png)

Copy the script to cyberchef. Recipe From Base64 and Decode text (UTF-16LE (1200))
The output there you will see : FroMBASe64StRInG('aAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADAALgA1AA==')));$t='/news.php'

   ![Screenshot](Document_Images/image12.png)

copy the text: 'aAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADAALgA1AA==     to cyberchef with same recipe. You will see the http://10.10.10.5 . Then put the /news.php together http://10.10.10.5/news.php .

Then go to cyberchef using defang URL .
answer : hxxp[://]10[.]10[.]10[.]5/news[.]php

   ![Screenshot](Document_Images/image13.png)

  ![Screenshot](Document_Images/image14.png)
