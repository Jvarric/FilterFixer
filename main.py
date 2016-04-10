import socket
import re

REGEX = re.compile(r'(.+?),(.*),(.+)')


def ip_gateway_to_service(filters):
    ip = re.compile(r'''
        (?P<ip>                         # Start IP section
        (?:25[0-5]|2[0-4]\d|1?\d?\d).   # Grab first octet
        (?:25[0-5]|2[0-4]\d|1?\d?\d).   # Grab second octet
        (?:25[0-5]|2[0-4]\d|1?\d?\d).   # Grab third octet
        (?:25[0-5]|2[0-4]\d|1?\d?\d)),  # Grab last octet
        (?P<netmask>                    # Start netmask section
        (?:25[0-5]|2[0-4]\d|1?\d?\d).   # Grab first octet
        (?:25[0-5]|2[0-4]\d|1?\d?\d).   # Grab second octet
        (?:25[0-5]|2[0-4]\d|1?\d?\d).   # Grab third octet
        (?:25[0-5]|2[0-4]\d|1?\d?\d)),  # Grab last octet
        (?:(?P<action>.+),)?            # Action to take if blocklist entry
        (?P<comment>.*)''',             # Optional comment
                    re.I | re.X)
    my_list = []

    for line in filters:
        # Strip newline character
        line = line.rstrip()
        match = ip.match(line)

        if match:
            if match.group('action') is None:
                action = "exempt"
            else:
                # Pull action line into a string as lowercase
                action = ''.join(match.group('action'))
                action = action.lower()

            # If action was tag or quarantine, set to block since BESS doesn't support tag or quarantine
            if (action == "tag") or (action == "quarantine"):
                action = "block"

            # Join back into a single line matching BESS formatting
            match = ','.join(match.group('ip', 'netmask')) + "," + action + "," + ''.join(match.group('comment'))

            # Add newly formatted line to list
            my_list.append(match)

    # Remove None entries from list and sort
    list(filter(None.__ne__, my_list))
    my_list.sort(key=lambda x: x.split(',', maxsplit=1)[0])

    return my_list


def sender_gateway_to_service(filters):
    sender_allow = re.compile(r'(.+?),(.*)', re.I)
    sender_block = re.compile(r'(.+?),(.*),(block|quarantine|tag)', re.I)
    my_list = []

    for line in filters:
        # Strip newline character
        line = line.rstrip()
        match = sender_block.match(line)
        if match:
            # Join pattern, action, and comment in proper order, ensuring action is lowercase
            action = ''.join(match.group(3))
            action = action.lower()

            # If action was tag, change to quarantine since BESS doesn't support tag
            if action == "tag":
                action = "quarantine"

            # Join back into a single line matching BESS formatting
            match = ''.join(match.group(1)) + "," + action + "," + ''.join(match.group(2))
        else:
            match = sender_allow.match(line)
            # Join back into a single line matching BESS formatting
            match = ''.join(match.group(1)) + ",exempt," + ''.join(match.group(2))

        # Add newly formatted line to list
        my_list.append(match)

    # Remove None from list entries and sort
    list(filter(None.__ne__, my_list))
    my_list.sort(key=lambda x: x.split(',', maxsplit=1)[0])

    return my_list


def recip_gateway_to_service():
    pass


def attach_gateway_to_service():
    pass


def content_gateway_to_service():
    pass


def main():

    print('What filter do you want to test?')
    i = input()

    if i == "sender":
        file = "sender_filters.txt"
    elif i == "ip":
        file = "ip_filters.txt"
    else:
        exit()
    with open(file) as my_file:
        filters = my_file.readlines()

    if i == "sender":
        output = sender_gateway_to_service(filters)
        print('Email Address,"Policy (block, exempt, quarantine)",Comment (optional)')
    elif i == "ip":
        output = ip_gateway_to_service(filters)
        print('IP Address,Netmask,"Policy (block, exempt)",Comment (optional)')
    else:
        exit()

    print('\n'.join(output))

main()
