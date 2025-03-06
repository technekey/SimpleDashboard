#!/usr/bin/env python3
import json
from getpass import getpass
from argon2 import PasswordHasher

def main():
    default_brand = "Technekey"
    brand_input = input(f"Enter brand name (default={default_brand}): ").strip()
    brand = brand_input if brand_input else default_brand

    username = input("Enter admin username: ")
    password = getpass("Enter admin password: ")

    default_host = "0.0.0.0"
    host_input = input(f"Enter host (default={default_host}): ").strip()
    host = host_input if host_input else default_host

    default_port = "5123"
    port_input = input(f"Enter port (default={default_port}): ").strip()
    port = port_input if port_input else default_port

    ph = PasswordHasher()
    hashed_password = ph.hash(password)

    config = {
        "APP_BRAND": brand,
        "ADMIN_USERNAME": username,
        "ADMIN_PASSWORD_HASH": hashed_password,
        "HOST": host,
        "PORT": int(port)
    }

    with open("config.json", "w") as f:
        json.dump(config, f, indent=2)

    print("Configuration saved to config.json.")

if __name__ == "__main__":
    main()
