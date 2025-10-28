#!/usr/bin/env python3
import os
import sys
import subprocess

def install_requirements():
    """Install required packages"""
    packages = ['flask', 'werkzeug']
    
    for package in packages:
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
            print(f"✅ {package} installed successfully")
        except subprocess.CalledProcessError:
            print(f"❌ Failed to install {package}")

def create_folders():
    """Create necessary folders"""
    folders = ['templates', 'uploads']
    
    for folder in folders:
        if not os.path.exists(folder):
            os.makedirs(folder)
            print(f"✅ Created {folder}/ folder")

def main():
    print("🚀 Setting up Secure File Sharing App...")
    print("=" * 60)
    print("🌟 Features: 5GB Files • Security Scanning • Private Files")
    print("=" * 60)
    
    # Create folders
    create_folders()
    
    # Install requirements
    print("\n📦 Installing dependencies...")
    install_requirements()
    
    print("\n" + "=" * 60)
    print("✅ Setup completed successfully!")
    print("\n🎯 Next steps:")
    print("1. Run: python app.py")
    print("2. The app will start on http://localhost:5000")
    print("3. Upload files with security scanning")
    print("4. View your files at: /my-files")
    print(f"5. Admin access at: /admin/files?token=admin123")
    
    print("\n🔒 Security features:")
    print("   • Dangerous file type blocking")
    print("   • User session isolation")
    print("   • File safety scanning")
    print("   • Private file ownership")
    
    print("\n🚀 Ready for secure file sharing!")

if __name__ == "__main__":
    main()