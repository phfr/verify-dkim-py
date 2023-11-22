import dkim
import sys
from email import message_from_string
from datetime import datetime

def verify_and_extract_dkim_headers(email_content):
    # Parse the email content into an email message
    msg = message_from_string(email_content)

    # Extract the DKIM-Signature header
    dkim_signature_header = msg.get("DKIM-Signature")

    if dkim_signature_header:
        try:
            # Verify the DKIM signature
            dkim.verify(msg.as_bytes(), logger=None)

            # If verification did not raise an exception, the signature is valid
            # Extract the timestamp from the DKIM-Signature header
            timestamp_field = next((field for field in dkim_signature_header.split(';') if field.strip().startswith('t=')), None)

            if timestamp_field:
                timestamp = int(timestamp_field.split('=')[1])
                # Convert the Unix timestamp to a human-readable date and time
                date_time = datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S UTC')
                print(f"DKIM Signature is valid. Date: {date_time}")

            # Extract and print header fields from the 'h=' tag
            h_tag_value = next((field.split('=')[1].strip() for field in dkim_signature_header.split(';') if field.strip().startswith('h=')), None)

            if h_tag_value:
                # Split the value of the 'h' tag to get individual header fields
                header_fields = h_tag_value.split(':')

                # Print the extracted header fields
                print("DKIM Header Fields:")
                for field_name in header_fields:
                    field_name = field_name.strip()
                    header_content = msg.get(field_name, "")
                    print(f" - {field_name}: {header_content}")

            else:
                print("No 'h=' tag found in DKIM-Signature header.")

        except dkim.ValidationError as e:
            print(f"DKIM Signature verification failed: {str(e)}")

        except dkim.DNS_ERROR as e:
            print(f"DKIM Signature verification failed. DNS lookup error: {str(e)}")

        except Exception as e:
            print(f"Error during DKIM verification: {str(e)}")

    else:
        print("DKIM-Signature header not found.")

# Read email content from stdin
email_content = sys.stdin.read()

verify_and_extract_dkim_headers(email_content)
