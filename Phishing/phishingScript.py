import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os
from dotenv import load_dotenv
import time
import random
from email.utils import formatdate, make_msgid

# Load environment variables from .env file
load_dotenv()

def send_email(recipient_email, subject, html_content, plain_content=None):
    """
    Send an email with proper configurations for maximum deliverability
    
    Args:
        recipient_email (str): Email address of the recipient
        subject (str): Email subject
        html_content (str): HTML body of the email
        plain_content (str): Plain text version of the email (optional)
    """
    # If plain_content is not provided, create a basic version from html_content
    if not plain_content:
        # This is a basic conversion - a real implementation would be more sophisticated
        plain_content = html_content.replace('<br>', '\n').replace('</p><p>', '\n\n')
        # Remove any HTML tags
        import re
        plain_content = re.sub(r'<[^>]+>', '', plain_content)
    
    # Create the email message with both HTML and plain text parts
    msg = MIMEMultipart('alternative')
    
    # Set proper headers for deliverability
    sender_name = "Cairo University Ethical Hacking Team"
    sender_email = os.getenv('EMAIL_ADDRESS')
    msg['From'] = f"{sender_name} <{sender_email}>"
    msg['To'] = recipient_email
    msg['Subject'] = subject
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid(domain=os.getenv('EMAIL_DOMAIN', 'cairo-university.edu.eg'))
    
    # Add List-Unsubscribe header for deliverability and compliance
    msg['List-Unsubscribe'] = f"<mailto:unsubscribe@{os.getenv('EMAIL_DOMAIN', 'cairo-university.edu.eg')}?subject=unsubscribe>"
    
    # Always include a plain text version first (important for deliverability)
    msg.attach(MIMEText(plain_content, 'plain'))
    
    # Then include the HTML version
    msg.attach(MIMEText(html_content, 'html'))
    
    # SMTP server settings
    smtp_server = os.getenv("EMAIL_HOST", "smtp.cairo-university.edu.eg")
    smtp_port = int(os.getenv("EMAIL_PORT", 587))
    sender_email = os.getenv("EMAIL_ADDRESS")
    password = os.getenv("EMAIL_PASSWORD")
    
    try:
        # Create server connection
        server = smtplib.SMTP(smtp_server, smtp_port)
        print(f"Connecting to {smtp_server} on port {smtp_port}...")
        server.starttls()
        
        # Login to the email server
        server.login(sender_email, password)
        print(f"Logged in as {sender_email}.")
        
        # Send the email
        text = msg.as_string()
        server.sendmail(sender_email, recipient_email, text)
        print(f"Email sent successfully to {recipient_email}.")
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False
    finally:
        server.quit()

def send_batch_emails(filename, subject, html_template, batch_size=20, delay_between_batches=120):
    """
    Send emails to a list of recipients in batches with delays between batches
    to prevent triggering rate limits.
    
    Args:
        filename (str): Path to the file containing email addresses (one per line)
        subject (str): Email subject
        html_template (str): HTML template for the email body
        batch_size (int): Number of emails to send in each batch
        delay_between_batches (int): Delay in seconds between batches
    """
    try:
        with open(filename, "r") as file:
            recipient_emails = file.read().splitlines()
    except Exception as e:
        print(f"Error reading email list file: {e}")
        return
    
    total_emails = len(recipient_emails)
    print(f"Preparing to send emails to {total_emails} recipients in batches of {batch_size}")
    
    # Process recipients in batches
    for i in range(0, total_emails, batch_size):
        batch = recipient_emails[i:i+batch_size]
        print(f"Sending batch {i//batch_size + 1} ({len(batch)} emails)...")
        
        for email in batch:
            # Add any personalization needed for the email
            html_content = html_template
            
            # Add a small random delay between individual emails (1-3 seconds)
            time.sleep(random.uniform(1, 3))
            
            # Send the email
            success = send_email(email, subject, html_content)
            if not success:
                print(f"Failed to send to {email}, continuing with next recipient")
        
        # If this isn't the last batch, wait before sending the next batch
        if i + batch_size < total_emails:
            wait_time = delay_between_batches + random.uniform(-10, 10)  # Add some randomness
            print(f"Batch complete. Waiting {wait_time:.0f} seconds before sending next batch...")
            time.sleep(wait_time)
    
    print("Email notification campaign completed.")

if __name__ == "__main__":
    email_list_file = "./student_emails.txt"
    
    email_subject = "Cairo University Ethical Hacking Seminar Announcement"
    html_email_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Cairo University Ethical Hacking Seminar Announcement</title>
    </head>
    <body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background-color: #f9f9f9; margin: 0; padding: 0;">
        <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
            <!-- Header with logo -->
            <div style="background-color: #003B49; padding: 20px; text-align: center;">
                <img src="https://eng.cu.edu.eg/wp-content/uploads/2014/12/logo221.png" alt="Cairo University Logo" style="max-width: 180px; height: auto;">
            </div>
            
            <!-- Main content -->
            <div style="padding: 30px 25px;">
                <h2 style="color: #003B49; margin-top: 0; margin-bottom: 15px;">Upcoming Ethical Hacking Seminar</h2>
                
                <p>Dear Student,</p>
                
                <p>The Cairo University Ethical Hacking Team is pleased to invite you to our upcoming seminar on <strong>Cybersecurity Best Practices</strong>.</p>
                
                <p style="color: #555;">This seminar will cover essential skills and knowledge to help you enhance your understanding of information security principles.</p>
                
                <div style="background-color: #f5f7fa; border-left: 4px solid #003B49; padding: 15px; margin: 20px 0;">
                    <p style="margin: 0; font-weight: 500;"><strong>Date:</strong> May 15, 2025</p>
                    <p style="margin: 5px 0; font-weight: 500;"><strong>Time:</strong> 2:00 PM - 4:00 PM</p>
                    <p style="margin: 5px 0; font-weight: 500;"><strong>Location:</strong> Engineering Building, Room 203</p>
                </div>
                
                <!-- Topics to be covered -->
                <h3 style="color: #003B49; margin-top: 20px; margin-bottom: 10px;">Topics include:</h3>
                <ul style="color: #555; margin-bottom: 20px;">
                    <li>Network Security Fundamentals</li>
                    <li>Modern Encryption Techniques</li>
                    <li>Threat Detection and Prevention</li>
                    <li>Hands-on Security Tools Workshop</li>
                </ul>
                
                <!-- CTA Button -->
                <div style="text-align: center; margin: 30px 0;">
                    <a href="https://eng.cu.edu.eg/en/" style="background-color: #003B49; color: #ffffff; text-decoration: none; padding: 12px 30px; border-radius: 4px; font-weight: 600; display: inline-block;">Register for Seminar</a>
                </div>
                
                <p>If you have any questions, please contact our team at <a href="mailto:ethicalhacking.edu.cu@gmail.com" style="color: #003B49; text-decoration: none;">ethicalhacking.edu.cu@gmail.com</a>.</p>
                
                <p>We look forward to seeing you there!</p>
                
                <p>Best regards,<br><strong>Cairo University Ethical Hacking Team</strong></p>
            </div>
            
            <!-- Footer -->
            <div style="background-color: #f5f7fa; padding: 20px; text-align: center; font-size: 12px; color: #666; border-top: 1px solid #eeeeee;">
                <p>© 2025 Cairo University Ethical Hacking Team. All rights reserved.</p>
                <p>This email was sent to students registered with the Ethical Hacking course.</p>
                <p><a href="https://eng.cu.edu.eg/en/faq/" style="color: #003B49; text-decoration: none;">FAQ</a> | <a href="https://eng.cu.edu.eg/en/contact-us/" style="color: #003B49; text-decoration: none;">Contact Us</a></p>
                <p>Ethical Hacking Team, Faculty of Engineering, Cairo University, Giza, Egypt</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    # Send emails in batches of 20 with a 2-minute delay between batches
    send_batch_emails(email_list_file, email_subject, html_email_template, batch_size=20, delay_between_batches=120)