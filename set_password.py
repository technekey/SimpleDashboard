#!/usr/bin/env python3
import json
import os
from getpass import getpass
from argon2 import PasswordHasher
from cryptography.fernet import Fernet

def main():
    # 1) Generate a new Fernet key so we can encrypt the weather key.
    new_key = Fernet.generate_key().decode()
    print("A new Fernet key has been generated:")
    print(new_key)
    print("\nPlease store it securely and export it before running the app, e.g.:")
    print(f'  export FERNET_SECRET="{new_key}"')
    print("Or add that line to your ~/.bashrc or ~/.zshrc.\n")

    # 2) Prompt for brand, admin username/password, host, port
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

    # 3) Optionally configure weather
    print("!!!OPTIONAL: The following info is optional for weather widget.!!!")
    print("\nOptional: Configure Weather via OpenWeatherMap")
    print("Get an API key from https://home.openweathermap.org/users/sign_up (Check free usage limits).")
    weather_key = input("Enter your OpenWeatherMap API key (or press Enter to skip): ").strip()

    if weather_key:
        # Encrypt the weather key with our new Fernet key
        fernet = Fernet(new_key.encode())
        encrypted_weather_key = fernet.encrypt(weather_key.encode()).decode()

        default_city = "ottawa"
        city_input = input(f"Enter city name for weather (default={default_city}): ").strip()
        city_name = city_input if city_input else default_city
    else:
        encrypted_weather_key = ""
        city_name = ""

    # 4) Ask if debug insights should be enabled
    debug_input = input("Enable debug insights in admin panel? (y/N): ").strip().lower()
    debug_insights = (debug_input == 'y')

    # 5) Write config.json
    config = {
        "APP_BRAND": brand,
        "ADMIN_USERNAME": username,
        "ADMIN_PASSWORD_HASH": hashed_password,
        "HOST": host,
        "PORT": int(port),
        "OPENWEATHER_API_KEY_ENC": encrypted_weather_key,  # ciphertext only
        "CITY_NAME": city_name,
        "DEBUG_INSIGHTS": debug_insights
    }

    with open("config.json", "w") as f:
        json.dump(config, f, indent=2)

    print("\nConfiguration saved to config.json.")
    if not weather_key:
        print("Weather configuration was skipped. The weather widget can be hidden/disabled in your app logic.")
    else:
        print("Weather key has been encrypted and stored in config.json.")
        print("Remember to export the Fernet key (FERNET_SECRET) before running the app!")

    if debug_insights:
        print("Debug Insights feature is ENABLED. System analytics will be visible in Admin Panel.")
    else:
        print("Debug Insights feature is DISABLED. System analytics will NOT be shown.")

if __name__ == "__main__":
    main()

