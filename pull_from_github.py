#!/usr/bin/env python3
"""
Script to check if the attack-stix-data folder exists and clone it from GitHub if it doesn't.
"""

import os
import subprocess
import sys
from pathlib import Path

def run_command(command, cwd=None):
    """
    Run a shell command and return the result.
    
    Args:
        command (list): Command to run as a list of strings
        cwd (str, optional): Working directory to run the command in
    
    Returns:
        tuple: (success: bool, output: str, error: str)
    """
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            check=True
        )
        return True, result.stdout.strip(), result.stderr.strip()
    except subprocess.CalledProcessError as e:
        return False, e.stdout.strip() if e.stdout else "", e.stderr.strip() if e.stderr else str(e)

def check_git_installed():
    """Check if git is installed on the system."""
    success, _, _ = run_command(["git", "--version"])
    return success

def clone_repository(repo_url, target_dir):
    """
    Clone a git repository to the target directory.
    
    Args:
        repo_url (str): URL of the git repository
        target_dir (str): Directory where the repository should be cloned
    
    Returns:
        bool: True if successful, False otherwise
    """
    print(f"Cloning repository from {repo_url}...")
    success, output, error = run_command(["git", "clone", repo_url, target_dir])
    
    if success:
        print(f"✅ Successfully cloned repository to {target_dir}")
        return True
    else:
        print(f"❌ Failed to clone repository: {error}")
        return False

def main():
    """Main function to check for folder and clone if necessary."""
    # Repository details
    repo_url = "https://github.com/mitre-attack/attack-stix-data.git"
    folder_name = "attack-stix-data"
    
    # Get the current script directory
    script_dir = Path(__file__).parent.absolute()
    target_path = script_dir / folder_name
    
    print(f"Checking for folder: {target_path}")
    
    # Check if git is installed
    if not check_git_installed():
        print("❌ Git is not installed or not accessible. Please install git first.")
        sys.exit(1)
    
    # Check if the folder already exists
    if target_path.exists() and target_path.is_dir():
        print(f"✅ Folder '{folder_name}' already exists at {target_path}")
        
        # Check if it's a git repository
        git_dir = target_path / ".git"
        if git_dir.exists():
            print("📁 Directory appears to be a git repository")
            
            # Optionally check if it's the correct repository
            success, output, _ = run_command(["git", "remote", "get-url", "origin"], cwd=str(target_path))
            if success and repo_url in output:
                print(f"✅ Repository origin matches expected URL: {repo_url}")
            else:
                print(f"⚠️  Repository origin doesn't match expected URL: {repo_url}")
        else:
            print("⚠️  Directory exists but is not a git repository")
    else:
        print(f"📂 Folder '{folder_name}' does not exist. Cloning from GitHub...")
        
        # Clone the repository
        if clone_repository(repo_url, str(target_path)):
            print("🎉 Repository successfully cloned!")
        else:
            print("💥 Failed to clone repository. Please check your internet connection and try again.")
            sys.exit(1)

if __name__ == "__main__":
    main()