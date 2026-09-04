import os, sys
required = ["POSTGUARD_SECRET","DATABASE_URL","POSTGUARD_PUBLIC_URL",
            "POSTGUARD_EMAIL_FROM","POSTGUARD_ADMIN_EMAIL"]
missing = [k for k in required if not os.getenv(k)]
if missing:
    print("Missing required production settings:", ", ".join(missing))
    sys.exit(1)
print("Core production environment settings are present.")
