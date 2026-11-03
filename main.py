from pathlib import Path

print("=" * 50)
print("       PURPLESHIELD AI")
print("       Cybersecurity Platform")
print("=" * 50)

def initialize_app():
    print("\nInitializing PurpleShield AI...")

    folders = [
        "frontend",
        "tests",
        "data"
    ]

    for folder in folders:
        Path(folder).mkdir(exist_ok=True)

    print("Project environment initialized!")
    print("All systems ready.")

if __name__ == "__main__":
    initialize_app()