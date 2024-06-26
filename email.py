# Import smtplib for the actual sending function
import smtplib

# Import the email modules we'll need
from email.mime.text import MIMEText

# Open a plain text file for reading.  For this example, assume that
# the text file contains only ASCII characters.
msg = "hi this is a test"

# me == the sender's email address
# you == the recipient's email address
msg['Subject'] = "test"
msg['From'] = "timothy.yang@coffeblock.com"
msg['To'] = "timothy.yang@thekingsschool.org"
# Send the message via our own SMTP server, but don't include the
# envelope header.
s = smtplib.SMTP('mail.coffeblock.com')
s.sendmail("timothy.yang@coffeblock.com", ["timothy.yang@thekingsschool.org"], msg.as_string())
s.quit()