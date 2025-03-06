# SimpleDashboard
This is a super simple dashboard for selfhosted applications. This is nothing fancy, admin can add/remove applications to the dashboard, whereas other users can use them. This also show basic system stats, like CPU Usage, Memory, Number of users, CPU Temp etc. 



# Installation

1. Install dependencies

```
pip3 -r requirements.txt
```

2. Setup admin password and Dashboard title

```
python3 set_password.py
Enter brand name (default=Technekey):
Enter admin username: admin
Enter admin password:
Configuration saved to config.json.
```

3. Start the app

```
python app.py
```

## Note: 
About setting password, Currenlty this app do not store the password in database, it store the password as hash(argon2) into the config.json file.  The script `set_password.py` will walk through the setup. 
