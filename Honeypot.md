# Setting Up a Honeypot with Azure Virtual Machine and Geolocation Analysis

## Objective

In this lab, I demonstrate how to set up a honeypot using an Azure Virtual Machine, collect data from failed Remote Desktop Protocol (RDP) login attempts, and analyze the geographic origin of the attacks. The logs are visualized on Azure Sentinel, providing actionable insights into attack patterns and locations.

### Skills Learned
- Configuring Azure Virtual Machines and Log Analytics.
- Collecting and analyzing failed login attempts (Event ID: 4625).
- Extracting and visualizing geolocation data using custom scripts.
- Leveraging Microsoft Sentinel for security data analysis.

### Tools Used
- Azure Virtual Machines and Microsoft Sentinel.
- PowerShell for custom logging scripts.
- Azure Log Analytics for log ingestion and querying.
- IP geolocation API for mapping attack origins.


## Result Video
https://www.youtube.com/watch?v=AqfTKpVqyxE
---

## Steps

### Step 1: Creating a Virtual Machine and Resource Group

I created a **Resource Group** and set up a virtual machine, configuring it with the following details:
- **Zone:** Zone 3 (for compatibility with the selected Windows 10 image).
- **Admin Account:**
  - Username: `####`
  - Password: `###########`

![image](https://github.com/user-attachments/assets/b72d4124-0730-4dc0-b6d5-bf62c5bb1d29)





---

### Step 2: Configuring Networking

In the **Networking** tab, I adjusted NIC settings to **Advanced** and modified firewall rules to allow external connections, enabling the VM to act as a honeypot.

- **Default Rule**: Deleted.
- **Custom Rule**: Added to make the VM discoverable.

**SET NIC SETTINGS TO ADVANCED**
![image](https://github.com/user-attachments/assets/34c20bc0-ae61-481e-bbf7-a1636c9a6488)



**CREATE CUSTOM RULE**
![image](https://github.com/user-attachments/assets/9b6c980a-db69-4a7e-9ffb-e3bd8142dff1)


---

### Step 3: Setting Up Log Analytics

I created a **Log Analytics Workspace** and connected it to the VM:
1. Navigate to **Microsoft Defender for Cloud**.
![image](https://github.com/user-attachments/assets/276c5bd2-6f41-430e-9a05-7acc9f36676e)

2. Enable **Defender** and set **Data Collection** to **All Events**.
![image](https://github.com/user-attachments/assets/b0a6ac8e-a1f4-4e46-9347-bce6ee3691a3)

3. Connect the **Log Analytics Workspace** to the VM. (Must Click Connect or it will say "Not connected")

![image](https://github.com/user-attachments/assets/60be00d1-6c29-4f0d-9e40-59b8fc03f55a)


---





### Step 4: Deploying Microsoft Sentinel

- I deployed Microsoft Sentinel and connected it to the Log Analytics Workspace.
![image](https://github.com/user-attachments/assets/fcf80fa7-6c9f-411f-9073-057cd4243962)

- Sentinel will aggregate the log data and provide geolocation insights.

![image](https://github.com/user-attachments/assets/0c4574d6-33d3-4ae7-a2eb-543573a571e8)

- Sentinel is a cloud-based SIEM platform that helps analysts detect, investigate and respond to threats. It is a vital part of the lab.
---

### Step 5: Connecting Via Remote Desktop

I connect to the VM via Remote Desktop. It is a simple process.

- From the start menu type "Remote Desktop" and you will be met with the following application.
![image](https://github.com/user-attachments/assets/e85be534-b429-4a4c-b40e-71ee47a8de99)

- Paste the Virtual Machines Ip and log into the server with the user and password set with the VM.
![image](https://github.com/user-attachments/assets/56e29100-ec51-46f8-9d21-6b66018efbc9)

- Every failed login attempt will be logged as an "Audit failure" which will still help with the lab.
![image](https://github.com/user-attachments/assets/c950b48d-c48c-4134-b377-08a669fa56d5)

---


### Step 6: Capturing Failed Login Attempts

Using the VM's **Event Viewer**, I monitored failed login attempts under `Windows Logs -> Security`.

![image](https://github.com/user-attachments/assets/6d33eff1-fc08-43c4-8a90-e529c3e5b611)

- The log from the event Viewer will help us format the Geo location data later.
- The next step is to take the information from the VM's event viewer log and paste it into the Geo location tool https://ipgeolocation.io/
- The geolocation tool will take the associated IP with every audit failure and help mark its location on a map.
- We will visualize the IP's location in Sentinel

---



### Step 7: Preparing the Virtual Machine for Attack.

- Before we can move further we want to ensure that our virtual machine is a prime target for attackers to try and launch an assualt.
- Up to this point we have made the VM discoverable but not fully vulnerable to attack.
- To fully entice attackers we will start by disabling the VM's firewall.

1.) Check and see if the firewall is operational.

- From my normal computer, outside of the virtual machine, I go to the start menu and type ```CMD```
- This will launch the command prompt
- I then begin to ping the virtual machines IP address with the following command
```Ping 20.51.108.222 -t```
- I use -t so that it will continue pinging until I stop it.
  
![image](https://github.com/user-attachments/assets/fdc58355-95ad-463d-be08-f8e948371c90)

- The request timeouted responses tell us that the firewall is still fully operational on the VM
  
2.) Disable the Firewall on the VM

- Heading back to the VM I find the firewall by heading to the windows start -> wf.msc
- From here I simple head to network settings and disable the firewall state for ```Domain```, ```Private``` and ```Public``` Profiles

![image](https://github.com/user-attachments/assets/3ca0a26a-92e3-48f5-8e04-9b14a95a2fce)

3.) Test if the firewall is still up
- Now heading back outside of the VM I can use the command prompt to see if we are able to probe the server
![image](https://github.com/user-attachments/assets/e02bfc3d-4546-4435-8279-c08f3a49f257)

- almost instantly I recieve a response.
---




### Step 8: Custom Logging Script in PowerShell

- With the virtual machine primed for attack we now have to write a powershell script to take the Audit Failure's from the VM's event logger and reference them with the Geolocation data from the ipgeolocatiom.io website. 
- The script will Automate the process of analyzing the failed RDP login attempts.
  
# Main Functions Script Overview

1.) Event Log extraction
- Because Event Viewer references Audit Failure with the event ID 4625 the script only has to search for that EventID and parse it out of the rest of the log
```$XMLFilter = @'
<QueryList> 
   <Query Id="0" Path="Security">
         <Select Path="Security">
              *[System[(EventID='4625')]]
          </Select>
    </Query>
</QueryList> 
'@
```

2.) It then references ```ipgeolocatiom.io``` to map the Ip addressess with each failed login

3.) When the data is extracted it compiles it with the geolocation data into a custom log folder named "failed_rdp.logs"
```# Get the current contents of the log file
$log_contents = Get-Content -Path $LOGFILE_PATH

# Do not write to the log file if the log already exists
if (-Not ($log_contents -match "$($timestamp)") -or ($log_contents.Length -eq 0)) {
    
    # Announce the gathering of geolocation data and pause for a second to avoid API rate-limiting
    Start-Sleep -Seconds 1

    # Make web request to the geolocation API
    $API_ENDPOINT = "https://api.ipgeolocation.io/ipgeo?apiKey=$($API_KEY)&ip=$($sourceIp)"
    $response = Invoke-WebRequest -UseBasicParsing -Uri $API_ENDPOINT

    # Parse the API response
    $responseData = $response.Content | ConvertFrom-Json
    $latitude = $responseData.latitude
    $longitude = $responseData.longitude
    $state_prov = $responseData.state_prov
    if ($state_prov -eq "") { $state_prov = "null" }
    $country = $responseData.country_name
    if ($country -eq "") { $country = "null" }

    # Write the extracted and geolocation data to the custom log file
    "latitude:$($latitude),longitude:$($longitude),destinationhost:$($destinationHost),username:$($username),sourcehost:$($sourceIp),state:$($state_prov),country:$($country),label:$($country) - $($sourceIp),timestamp:$($timestamp)" | Out-File $LOGFILE_PATH -Append -Encoding utf8

    # Output the log entry to the console for debugging or review
    Write-Host -BackgroundColor Black -ForegroundColor Magenta "latitude:$($latitude),longitude:$($longitude),destinationhost:$($destinationHost),username:$($username),sourcehost:$($sourceIp),state:$($state_prov),label:$($country) - $($sourceIp),timestamp:$($timestamp)"
}
```


- Pasting the script into Powershell and Running it will begin our process. It is important to make sure Powershell is being ran as an administrator
![image](https://github.com/user-attachments/assets/6adfd6e6-bc7a-499c-8364-8d54d87c7420)

- The script is working when we begin to see all of the audit failures being logged by powershell
![image](https://github.com/user-attachments/assets/f4d69fad-8c97-478c-adbf-91220c1fd9ba)


- For reference, this is what the ```Failed_rdp.log``` File looks like. Everything above the red bracket are sample text for the script. Everything in the red bracket are our actual failed login attempts.
![image](https://github.com/user-attachments/assets/4a0aaee6-65db-41b3-a40c-3eeeef718caa)
---

### Step 9: Move the Geodata from the VM to Azure 

- Exiting the VM and heading into Azure I use the LAW honeypot area to set up a custom log
- Because the Honeypot files are not accessible outside of the VM we have to manually copy the data from the ```Failed_RDP.log``` File and create a new one to train our Honeypot LAW on what to look for.
![image](https://github.com/user-attachments/assets/c4a13dbb-dd41-4ea6-ab0a-a039eee94c7a)


- after waiting some time Azure will be able to recall the log data from the VM 

![image](https://github.com/user-attachments/assets/d1b15b9f-fb71-41d6-a334-b41ef7688145)



---


### Step 10: Organize the data from the Log Analytics Workspace into distinct fields to plot.
- In the workbook I use the following query. The Query will ensure we do not have to manually define each part of the log and tell it what to look for in the data.
```FAILED_RDP_WITH_GEO_CL 
| extend username = extract(@"username:([^,]+)", 1, RawData),
         timestamp = extract(@"timestamp:([^,]+)", 1, RawData),
         latitude = extract(@"latitude:([^,]+)", 1, RawData),
         longitude = extract(@"longitude:([^,]+)", 1, RawData),
         sourcehost = extract(@"sourcehost:([^,]+)", 1, RawData),
         state = extract(@"state:([^,]+)", 1, RawData),
         label = extract(@"label:([^,]+)", 1, RawData),
         destination = extract(@"destinationhost:([^,]+)", 1, RawData),
         country = extract(@"country:([^,]+)", 1, RawData)
| where destination != "samplehost"
| where sourcehost != ""
| summarize event_count=count() by timestamp, label, country, state, sourcehost, username, destination, longitude, latitude
```
- In short the query write the usernames in full with the timestamps, latitude, longitude, sourcehost, state etc.
- It makes sure to exclude any logs where the destination is "Sample host"
- And also excludes any logs where the samplehost is blank
- The final log formats the log in the exact order presented.
![image](https://github.com/user-attachments/assets/405a9870-507a-4483-81de-c8adfd87d71f)

---


### Step 11: Set up the Workbook
- The final step is to set up the workbook map using Microsoft Sentinel.
- We recall the query from above 
```FAILED_RDP_WITH_GEO_CL 
| extend username = extract(@"username:([^,]+)", 1, RawData),
         timestamp = extract(@"timestamp:([^,]+)", 1, RawData),
         latitude = extract(@"latitude:([^,]+)", 1, RawData),
         longitude = extract(@"longitude:([^,]+)", 1, RawData),
         sourcehost = extract(@"sourcehost:([^,]+)", 1, RawData),
         state = extract(@"state:([^,]+)", 1, RawData),
         label = extract(@"label:([^,]+)", 1, RawData),
         destination = extract(@"destinationhost:([^,]+)", 1, RawData),
         country = extract(@"country:([^,]+)", 1, RawData)
| where destination != "samplehost"
| where sourcehost != ""
| summarize event_count=count() by latitude, longitude, sourcehost, label, destination, country
```


![image](https://github.com/user-attachments/assets/74b53c89-0b63-4310-a48d-8e3c78c14e07)


- After running the Query I can use the dropdown Visualization option to list a map and see where every audit failure had come from so far.



- these were my results after just finishing the lab
![image](https://github.com/user-attachments/assets/b39b4d90-10f7-4d24-9e57-8de9d999f899)

- Every audit failure had come from my desktop when I was initially setting up the VM.



- After almost an hour these were my results 


### VM
![image](https://github.com/user-attachments/assets/ace520cb-1d74-4621-a8ed-12bff86143e1)

### MAP
![image](https://github.com/user-attachments/assets/1bc66c8c-a71b-4921-9c73-67c4a7df35ca)




```
