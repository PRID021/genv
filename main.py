import logging
import os
import platform
import re
import subprocess


def read_config_file():
    """Read identity files from the specified config file."""
    config_file_path = ".genv.config"
    if os.path.exists(config_file_path):
        with open(config_file_path, "r") as f:
            return [line.strip() for line in f.readlines() if line.strip()]
    return []


def setup_logging():
    """Set up logging configuration."""
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
    )


def get_ssh_config_path(identity_files):
    """Get the SSH config file path based on the operating system."""
    system = platform.system()

    if system == "Darwin":  # macOS
        ssh_config_path = os.path.expanduser("~/.ssh/config")
        identity_file_paths = [
            os.path.expanduser(f"~/.ssh/{file}") for file in identity_files
        ]
    elif system == "Windows":
        home_dir = os.path.expanduser("~")
        ssh_config_path = os.path.join(home_dir, ".ssh", "config").replace("\\", "/")
        identity_file_paths = [
            os.path.join(home_dir, ".ssh", f"{file}").replace("\\", "/")
            for file in identity_files
        ]
    elif system == "Linux":
        ssh_config_path = os.path.expanduser("~/.ssh/config")
        identity_file_paths = [
            os.path.expanduser(f"~/.ssh/{file}") for file in identity_files
        ]
    else:
        raise OSError(f"Unsupported OS: {system}")

    return ssh_config_path, identity_file_paths


def read_ssh_config(file_path):
    """Read the SSH config file if it exists."""
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            return f.read()
    return ""


def write_ssh_config(file_path, config_data):
    """Write or update the SSH config file."""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)

    with open(file_path, "w") as f:
        f.write(config_data)


def modify_identity_file(config, old_identity, new_identity):
    """Modify the IdentityFile path in the SSH config."""
    pattern = re.compile(rf"IdentityFile\s+{re.escape(old_identity)}")
    updated_config = pattern.sub(f"IdentityFile {new_identity}", config)
    return updated_config


def update_identity_file_in_config(existing_config, identity_file):
    """Update the IdentityFile in the SSH config."""
    pattern = re.compile(r"IdentityFile\s+.*")
    updated_config = pattern.sub(f"IdentityFile {identity_file}", existing_config)
    return updated_config


def start_ssh_agent():
    """Start the SSH agent and return its process ID."""
    try:
        result = subprocess.run(
            ["ssh-agent"], capture_output=True, text=True, check=True
        )
        for line in result.stdout.splitlines():
            if "SSH_AUTH_SOCK" in line or "SSH_AGENT_PID" in line:
                print(line)
    except subprocess.CalledProcessError:
        logging.error("Failed to start the SSH agent.")


def add_identity_to_ssh_agent(identity_file):
    """Add the specified identity file to the SSH agent."""
    try:
        subprocess.run(["ssh-add", identity_file], check=True)
        logging.info(f"Successfully added {identity_file} to the SSH agent.")
    except subprocess.CalledProcessError:
        logging.error(f"Failed to add {identity_file} to the SSH agent.")


def restart_ssh_agent():
    """Restart the SSH agent."""
    system = platform.system()
    try:
        if system == "Windows":
            # Kill any existing SSH agent on Windows
            subprocess.run(
                ["TASKKILL", "/F", "/IM", "ssh-agent.exe"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            logging.info("SSH agent terminated.")
        elif system == "Darwin":  # macOS
            # Kill any existing SSH agent on macOS
            subprocess.run(
                ["pkill", "ssh-agent"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            logging.info("SSH agent terminated.")
    except Exception as e:
        logging.error(f"Failed to kill SSH agent: {e}")

    start_ssh_agent()


def set_permissions(file_path):
    """Set permissions for the specified file to 600."""
    try:
        os.chmod(file_path, 0o600)  # Set file permissions to 600
        logging.info(f"Set permissions to 600 for {file_path}.")
    except Exception as e:
        logging.error(f"Failed to set permissions for {file_path}: {e}")


def main():
    setup_logging()
    identity_files = read_config_file()
    if not identity_files:
        logging.error("No identity files found in .genv.config.")
        return
    logging.info(f"Found identity files: {identity_files}")

    ssh_config_path, identity_file_paths = get_ssh_config_path(identity_files)
    existing_config = read_ssh_config(ssh_config_path)

    if not existing_config.strip():
        logging.warning("No existing SSH config found.")
        return

    set_permissions(ssh_config_path)

    for identity_file in identity_file_paths:
        set_permissions(identity_file)

    print("Select an identity file to use:")
    for index, identity_file in enumerate(identity_files):
        print(f"{index}: {identity_file}")

    try:
        selection = int(
            input("Enter the number of the identity file you want to use: ")
        )
        if selection < 0 or selection >= len(identity_files):
            raise ValueError("Invalid selection.")
    except ValueError as e:
        logging.error(f"Error: {e}. Please enter a valid number.")
        return

    selected_identity_file = identity_file_paths[selection]
    logging.info(f"Selected identity file: {selected_identity_file}")

    updated_config = update_identity_file_in_config(
        existing_config, selected_identity_file
    )

    write_ssh_config(ssh_config_path, updated_config)

    restart_ssh_agent()
    add_identity_to_ssh_agent(selected_identity_file)

    logging.info(f"Updated SSH config file at {ssh_config_path}")
    logging.info(f"The current IdentityFile in use is: {selected_identity_file}")


if __name__ == "__main__":
    main()
