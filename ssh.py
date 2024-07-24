from flask import Flask, request, jsonify, redirect, url_for, render_template, session
from flask import send_file
from netmiko import ConnectHandler
import paramiko
import os
import pandas as pd
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Set a secret key for session management

UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.route('/sshlogin', methods=['POST'])
def sshlogin():
    username = request.form['username']
    password = request.form['password']
    
    try:
        # Create an SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Connect to the SSH server
        ssh.connect('pglnetwork01', username=username, password=password)

        # Print success message
        print("SSH connection successful!")

        # Set session to indicate user is logged in
        session['logged_in'] = True

        # Redirect to main.html
        return render_template('main.html')
    except paramiko.AuthenticationException:
        # Print unsuccessful message
        print("Authentication failed. Please check your username and password.")
        
        # Redirect to login page
        return render_template('login.html')
    except paramiko.SSHException as e:
        # Print other SSH-related exceptions
        print(f"SSH error: {e}")
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        # Print other exceptions
        print(f"Error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/main')
def main():
    # Check if user is logged in
    if 'logged_in' in session:
        return render_template('main.html')
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    # Clear the session to log out the user
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/upload_excel', methods=['POST'])
def upload_excel():
    if 'logged_in' in session:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        if file and (file.filename.endswith('.xlsx') or file.filename.endswith('.xls')):
            filename = secure_filename(file.filename)
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(file_path)
            
            # Calculate the number of rows in all sheets including the first row
            total_rows = 0
            xls = pd.ExcelFile(file_path)
            for sheet_name in xls.sheet_names:
                df = pd.read_excel(xls, sheet_name=sheet_name)
                total_rows += len(df)+1
            
            # Send back the total message using alert
            total_message = f"Total number of rows: {total_rows}"
            return render_template('main.html', alert_message=total_message)
        else:
            return jsonify({'error': 'Invalid file type'}), 400
    else:
        return redirect(url_for('login'))



@app.route('/show_ip_configure', methods=['GET'])
def show_ip_configure():
    # Clear the devices list before processing new data
    devices.clear()

    # Read the entire Excel file
    xls = pd.ExcelFile('uploads/ip_addresses.xlsx')
    
    # Iterate through all sheets and process each row
    for sheet_name in xls.sheet_names:
        df = pd.read_excel(xls, sheet_name=sheet_name, header=None)
        for index, row in df.iterrows():
            ip_address = row[0]  # Assuming the IP address is in the first column
            run_commands_on_device(ip_address)
    
    # Generate the HTML file
    show_html()
    
     # Instead of sending the file, render the HTML content directly
    with open('templates/device_output.html', 'r') as file:
        html_content = file.read()
    return render_template('device_output.html', html_content=html_content)

#Switch 1
# List to store device information
devices = []

def run_commands_on_device(ip_address):
    device = {
        'device_type': 'cisco_ios',
        'ip': ip_address,
        'username': 'nwtools',
        'password': '!1Jst4Tls7!',
    }

    try:
        # Establish an SSH connection
        ssh_session = ConnectHandler(**device)

        # Execute your desired commands (e.g., show version)
        output = ssh_session.send_command('write memory')
        
        hostname = ssh_session.find_prompt().strip("#")
        
        # Append data to devices list
        devices.append((ip_address, hostname, output))
        
        # Create a dataframe from the devices list to create Log
        df = pd.DataFrame(devices, columns=['IP Address', 'Hostname', 'Status'])
        
        # Print the output or process it further
        print(f"Output for {ip_address}:\n{output}")
        
        # Save output to files (customize filenames as needed)
        with pd.ExcelWriter('Cisco_Device_Write.xlsx') as writer:
            df.to_excel(writer, sheet_name='Device_Write', index=False)

        # Close the SSH session
        ssh_session.disconnect()
        
        show_html()
        
        return True

    except Exception as e:
        print(f"Error for {ip_address}: {str(e)}")
        return False

# Create HTML output
def show_html():
    
    html_output = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Device Command Output</title>
        <style>
            table {
                width: 100%;
                border-collapse: collapse;
            }
            table, th, td {
                border: 1px solid black;
            }
            th, td {
                padding: 15px;
                text-align: left;
            }
            th {
                background-color: #f2f2f2;
            }
        </style>
    </head>
    <body>
        <h2>Device Command Output</h2>
        <table>
            <tr>
                <th>IP Address</th>
                <th>Hostname</th>
                <th>Status</th>
            </tr>
    """

    for device in devices:
        html_output += f"""
            <tr>
                <td>{device[0]}</td>
                <td>{device[1]}</td>
                <td>{device[2]}</td>
            </tr>
        """
    
    html_output += """
        </table>
        <p><a href="mac_address_page.html">MAC Address</a></p>
        <p><a href="/main">Back to Main Menu</a></p>
    </body>
    </html>
    """

    # Save HTML output to a file
    with open('templates/device_output.html', 'w') as file:
        file.write(html_output)
    
    print("HTML file generated successfully.")

if __name__ == '__main__':
    app.run(debug=True)
