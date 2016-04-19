import re


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

    my_filters = filters.splitlines()

    for line in my_filters:
        # Strip newline character
        line = line.rstrip()
        match = ip.match(line)

        if match:
            if match.group('action') is None:
                action = 'exempt'
            else:
                # Pull action line into a string as lowercase
                action = ''.join(match.group('action'))
                action = action.lower()

            # If action was tag or quarantine, set to block since BESS doesn't support tag or quarantine
            if (action == 'tag') or (action == 'quarantine'):
                action = 'block'

            # Join back into a single line matching BESS formatting
            match = ','.join(match.group('ip', 'netmask')) + ',' + action + ',' + ''.join(match.group('comment'))
            my_list.append(match)

    # Remove None entries from list and sort
    list(filter(None.__ne__, my_list))
    my_list.sort(key=lambda x: x.split(',', maxsplit=1)[0])

    output = '\n'.join(my_list)
    if output == '':
        return "No results. Go back and check for improper formatting"

    return output


def sender_gateway_to_service(filters):
    sender_allow = re.compile(r'(.+?),(.*)', re.I)
    sender_block = re.compile(r'(.+?),(.*),(block|quarantine|tag)', re.I)
    my_list = []

    my_filters = filters.splitlines()

    for line in my_filters:
        # Strip newline character
        line = line.rstrip()
        if line == 'Email Address/Domain,Comment' or line == 'Email Address/Domain,Comment,Action':
            continue
        match = sender_block.match(line)

        if match:
            # Join pattern, action, and comment in proper order, ensuring action is lowercase
            action = ''.join(match.group(3))
            action = action.lower()

            # If action was tag, change to quarantine since BESS doesn't support tag
            if action == 'tag':
                action = 'quarantine'

            # Join back into a single line matching BESS formatting
            match = ''.join(match.group(1)) + ',' + action + ',' + ''.join(match.group(2))
            my_list.append(match)
        else:
            match = sender_allow.match(line)
            # Join back into a single line matching BESS formatting
            if not match:
                continue
            match = ''.join(match.group(1)) + ',exempt,' + ''.join(match.group(2))
            my_list.append(match)

    # Remove None from list entries and sort
    list(filter(None.__ne__, my_list))
    my_list.sort(key=lambda x: x.split(',', maxsplit=1)[0])

    output = '\n'.join(my_list)
    if output == '':
        return "No results. Go back and check for improper formatting"

    return output


def recip_gateway_to_service(filters):
    recip_allow = re.compile(r'(.+?),(.*)', re.I)
    recip_block = re.compile(r'(.+?),(.+),(.*)', re.I)
    my_list = []

    my_filters = filters.splitlines()

    for line in my_filters:
        if line == 'Email Address/Domain,Comment' or line == 'Email Address/Domain,Action,Comment':
            continue
        match = recip_block.match(line)
        if match:
            continue

        match = recip_allow.match(line)
        if match:
            # Join pattern, action, and comment in proper order, ensuring action is lowercase
            match = ''.join(match.group(1)) + ',exempt,' + ''.join(match.group(2))
            my_list.append(match)

    # Remove None from list entries and sort
    list(filter(None.__ne__, my_list))
    my_list.sort(key=lambda x: x.split(',', maxsplit=1)[0])

    output = '\n'.join(my_list)
    if output == '':
        return "No results. Go back and check for improper formatting"

    return output


def attach_gateway_to_service(filters):
    return "This function not available"


def content_gateway_to_service(filters):
    content = re.compile(r'''
                         (?P<pattern>.+),                                         # Pattern
                         (?P<comment>.*),                                         # Comment
                         (?P<action>Block|Quarantine|Tag|Whitelist|Off),          # Inbound action
                         (?:Block|Quarantine|Tag|Whitelist|Off|Encrypt|Redirect), # Outbound action
                         (?P<subject>[01]),                                       # Apply to subject
                         (?P<header>[01]),                                        # Apply to header
                         (?P<body>[01])''',                                       # Apply to body
                         re.I | re.X)
    my_list = []

    my_filters = filters.splitlines()

    for line in my_filters:
        # Strip newline character
        line = line.rstrip()
        match = content.match(line)

        if match:
            # Join pattern, action, and comment in proper order, ensuring action is lowercase
            action = ''.join(match.group('action'))
            action = action.lower()

            # If action was tag, change to quarantine since BESS doesn't support tag
            if action == 'tag':
                action = 'quarantine'
            elif action == 'whitelist':
                action = 'allow'
            elif action == 'off':
                break

            # Join back into a single line matching BESS formatting and add entries for attachment, sender, recip
            match = ','.join(match.group('pattern', 'comment')) + ',' + action + ',' + \
                    ','.join(match.group('subject', 'header', 'body')) + ',0,0,0'

            # Add newly formatted line to list
            my_list.append(match)

    # Remove None from list entries and sort
    list(filter(None.__ne__, my_list))
    my_list.sort(key=lambda x: x.split(',', maxsplit=1)[0])

    output = '\n'.join(my_list)
    if output == '':
        return "No results. Go back and check for improper formatting"

    return output


def main():

    print('What filter do you want to test?')
    i = input()

    if i == 'sender':
        file = 'sender_filters.txt'
    elif i == 'ip':
        file = 'ip_filters.txt'
    elif i == 'content':
        file = 'content_filters.txt'
    else:
        exit()
    with open(file, encoding='utf-8') as my_file:
        filters = my_file.readlines()

    if i == 'sender':
        output = sender_gateway_to_service(filters)
        print('Email Address,"Policy (block, exempt, quarantine)",Comment (optional)')
    elif i == 'ip':
        output = ip_gateway_to_service(filters)
        print('IP Address,Netmask,"Policy (block, exempt)",Comment (optional)')
    elif i == 'content':
        output = content_gateway_to_service(filters)
        print('Pattern (regular expression),Action (block/allow/quarantine),"Match Filter (Comma-separated list of: '
              'subject, headers, body, attachments, sender, recipient)"')
    else:
        exit()

if __name__ == "__main__":
    main()
