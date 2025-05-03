import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os
from dotenv import load_dotenv
import time
import random
from email.utils import formatdate, make_msgid
from fpdf import FPDF

# Load environment variables from .env file
load_dotenv()

def create_dummy_pdf(output_path="seminar_details.pdf"):
    """
    Generate a dummy PDF with seminar details.
    """
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="Cairo University Ethical Hacking Seminar", ln=True, align='C')

    pdf.set_font("Arial", size=12)
    pdf.ln(10)
    pdf.multi_cell(0, 10, txt="""
Dear Student,

The Cairo University Ethical Hacking Team invites you to our upcoming seminar on:

Cybersecurity Best Practices

Date: May 15, 2025
Time: 2:00 PM - 4:00 PM
Location: Engineering Building, Room 203

Topics:
- Network Security Fundamentals
- Modern Encryption Techniques
- Threat Detection and Prevention
- Hands-on Security Tools Workshop

We look forward to seeing you there!

Best regards,
Cairo University Ethical Hacking Team
    """)
    pdf.output(output_path)

def send_email(recipient_email, subject, html_content, plain_content=None):
    """
    Send an email with proper configurations for maximum deliverability
    """
    if not plain_content:
        import re
        plain_content = html_content.replace('<br>', '\n').replace('</p><p>', '\n\n')
        plain_content = re.sub(r'<[^>]+>', '', plain_content)

    msg = MIMEMultipart('alternative')
    
    sender_name = "Cairo University Ethical Hacking Team"
    sender_email = os.getenv('EMAIL_ADDRESS')
    msg['From'] = f"{sender_name} <{sender_email}>"
    msg['To'] = recipient_email
    msg['Subject'] = subject
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid(domain=os.getenv('EMAIL_DOMAIN', 'cairo-university.edu.eg'))
    msg['List-Unsubscribe'] = f"<mailto:unsubscribe@{os.getenv('EMAIL_DOMAIN', 'cairo-university.edu.eg')}?subject=unsubscribe>"
    
    msg.attach(MIMEText(plain_content, 'plain'))
    msg.attach(MIMEText(html_content, 'html'))
    
    smtp_server = os.getenv("EMAIL_HOST", "smtp.cairo-university.edu.eg")
    smtp_port = int(os.getenv("EMAIL_PORT", 587))
    sender_email = os.getenv("EMAIL_ADDRESS")
    password = os.getenv("EMAIL_PASSWORD")

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        print(f"Connecting to {smtp_server} on port {smtp_port}...")
        server.starttls()
        server.login(sender_email, password)
        print(f"Logged in as {sender_email}.")
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
    try:
        with open(filename, "r") as file:
            recipient_emails = file.read().splitlines()
    except Exception as e:
        print(f"Error reading email list file: {e}")
        return

    total_emails = len(recipient_emails)
    print(f"Preparing to send emails to {total_emails} recipients in batches of {batch_size}")

    for i in range(0, total_emails, batch_size):
        batch = recipient_emails[i:i+batch_size]
        print(f"Sending batch {i//batch_size + 1} ({len(batch)} emails)...")
        
        for email in batch:
            html_content = html_template
            time.sleep(random.uniform(1, 3))
            success = send_email(email, subject, html_content)
            if not success:
                print(f"Failed to send to {email}, continuing with next recipient")
        
        if i + batch_size < total_emails:
            wait_time = delay_between_batches + random.uniform(-10, 10)
            print(f"Batch complete. Waiting {wait_time:.0f} seconds before sending next batch...")
            time.sleep(wait_time)

    print("Email notification campaign completed.")

if __name__ == "__main__":
    # Generate the seminar PDF
    create_dummy_pdf("seminar_details.pdf")

    email_list_file = "./student_emails.txt"
    email_subject = "Cairo University Ethical Hacking Seminar Announcement"

    # Use the actual public URL if you're hosting the PDF
    public_pdf_url = "https://drive.google.com/uc?export=download&id=1vyPIU5sDRoFFZJUTGryxBEbMGCTIyCAa"

    html_email_template = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Cairo University Ethical Hacking Seminar Announcement</title>
    </head>
    <body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background-color: #f9f9f9; margin: 0; padding: 0;">
        <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
            <div style="background-color: #003B49; padding: 20px; text-align: center;">
                <img src="https://eng.cu.edu.eg/wp-content/uploads/2014/12/logo221.png" alt="Cairo University Logo" style="max-width: 180px; height: auto;">
            </div>
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
                <h3 style="color: #003B49; margin-top: 20px; margin-bottom: 10px;">Topics include:</h3>
                <ul style="color: #555; margin-bottom: 20px;">
                    <li>Network Security Fundamentals</li>
                    <li>Modern Encryption Techniques</li>
                    <li>Threat Detection and Prevention</li>
                    <li>Hands-on Security Tools Workshop</li>
                </ul>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{public_pdf_url}" 
                       style="background-color: #003B49; color: #ffffff; text-decoration: none; padding: 12px 30px; border-radius: 4px; font-weight: 600; display: inline-block;" 
                       target="_blank" download>
                        Download Seminar PDF
                    </a>
                </div>
                <p>If you have any questions, please contact our team at <a href="mailto:ethicalhacking.edu.cu@gmail.com" style="color: #003B49; text-decoration: none;">ethicalhacking.edu.cu@gmail.com</a>.</p>
                <p>We look forward to seeing you there!</p>
                <p>Best regards,<br><strong>Cairo University Ethical Hacking Team</strong></p>
            </div>
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

    send_batch_emails(email_list_file, email_subject, html_email_template, batch_size=20, delay_between_batches=120)
