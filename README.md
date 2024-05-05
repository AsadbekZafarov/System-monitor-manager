Process Monitor

Process Monitor is a Python application that provides a graphical user interface (GUI) for monitoring running processes on a system. It allows users to view detailed information about each process, including PID, name, CPU usage, memory usage, user, and date-time. Additionally, the application offers functionalities to save process information to a file and send it via email.
Features

    Process Monitoring: Continuously monitors running processes and updates the GUI with real-time data.
    Start, Pause, Resume, and Stop Monitoring: Control the monitoring process according to your preferences.
    Save Processes to File: Save process information displayed in the GUI to a text file for future reference.
    Email Notification: Configure email settings to send process information as an attachment via email.

Requirements

    Python 3.x
    psutil library
    tkinter library
    smtplib library (for email functionality)



Usage

    Run the eventlog.py file:

    css

    python eventlog.py

    The Process Monitor GUI will open.
    Use the buttons provided to start, pause, resume, and stop monitoring processes.
    Click on "Save Processes" to save process information to a text file.
    Click on "Send to Email" to configure email settings and send process information via email.

Contributing

Contributions are welcome! If you have any suggestions, bug reports, or feature requests, please open an issue or submit a pull request.
