import sys
import re

REGEX = re.compile(r'(.+?),(.*),(.+)')


def ip():
    pass


def sender_gateway_to_service(filters):
    sender_allow = re.compile(r'(.+?),(.*)', re.I)
    sender_block = re.compile(r'(.+?),(.*),(block|quarantine|tag)', re.I)
    formatted_list = []
    match = []

    for line in filters:
        # Strip newline character
        line = line.rstrip()
        try:
            match = sender_block.match(line)
            if match:
                # print("block - {}".format(match.groups()))
                # Join pattern, action, and comment in proper order, ensuring action is lowercase
                action = ''.join(match.group(3))
                action = action.lower()

                # If action was tag, change to quarantine since BESS doesn't support tag
                if action == "tag":
                    action = "quarantine"

                # Reorder line to match BESS formatting
                match = ''.join(match.group(1)) + "," + action + "," + ''.join(match.group(2))
            else:
                match = sender_allow.match(line)
                # print("allow - {}".format(match.groups()))
                # Reorder line to match BESS formatting
                match = ''.join(match.group(1)) + ",exempt," + ''.join(match.group(2))
        # !!COME BACK TO THIS LATER!!
        except:
            e = sys.exc_info()
            print("Not a sender filter. Check formatting. Error: {}".format(e))

        # Save newly formatted line
        formatted_list.append(match)

    # Sort list before returning
    formatted_list.sort()

    return formatted_list


def recipient_gateway_to_service():
    pass


def attachment_gateway_to_service():
    pass


def content_gateway_to_service():
    pass


def main():
    with open('sender_filters.txt') as my_file:
        filters = my_file.readlines()

    output = sender_gateway_to_service(filters)

    print('\n'.join(output))
'''
    for line in filters:
        print(line, end="")
        line = line.rstrip()
        match = REGEX.match(line)

        if match:
            print("The matches are: {}".format(match.groups()))
            print("The re-ordered filter is: {}\n".format(', '.join(match.group(0, 1, 2, 3)) + ",blah"))
'''

main()
