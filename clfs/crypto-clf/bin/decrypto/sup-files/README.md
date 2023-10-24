## Configuration Files
This folder contains `.sup` files - configuration fields for the Nemea supervisor.

### Setup Hints
Copy configuration folder to Nemea's config folder:
```
cp -r decrypto/ /etc/nemea
```

Insert this to `/etc/nemea/supervisor_config_template.xml`:
```
<modules>
  <name>DeCrypto System</name>
  <enabled>false</enabled>
  <!-- include /etc/nemea/decrypto -->
</modules>
```
