# TODO
# Write and implement recipient filter function

import re


def remove_empty(my_list):
    clean_list = [x for x in my_list if x is not None]
    return clean_list


def get_sorted(my_list):
    # Only sort pattern before first comma
    my_list.sort(key=lambda x: x.split(',', maxsplit=1))
    output = '\n'.join(my_list)
    if output == '':
        return "No results. Go back and check for improper formatting"
    else:
        return output


def ip_convert(filters):
    ip = re.compile(r'''
                    (?P<ip>                         # Start IP section
                    (?:25[0-5]|2[0-4]\d|1?\d?\d).
                    (?:25[0-5]|2[0-4]\d|1?\d?\d).
                    (?:25[0-5]|2[0-4]\d|1?\d?\d).
                    (?:25[0-5]|2[0-4]\d|1?\d?\d)),
                    (?P<netmask>                    # Start netmask section
                    (?:25[0-5]|2[0-4]\d|1?\d?\d).
                    (?:25[0-5]|2[0-4]\d|1?\d?\d).
                    (?:25[0-5]|2[0-4]\d|1?\d?\d).
                    (?:25[0-5]|2[0-4]\d|1?\d?\d)),
                    (?:(?P<action>.+),)?            # Action to take if blocklist entry
                    (?P<comment>.*)''',
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

    my_list = remove_empty(my_list)
    output = get_sorted(my_list)

    return output


def sender_convert(filters):
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

    my_list = remove_empty(my_list)
    output = get_sorted(my_list)

    return output


def recip_convert(filters):
    recip_allow = re.compile(r'(.+?),(.*)', re.I)
    recip_block = re.compile(r'(.+?),(.+),(.*)', re.I)
    my_list = []

    my_filters = filters.splitlines()

    for line in my_filters:
        if line == 'Email Address/Domain,Comment' or line == 'Email Address/Domain,Action,Comment':
            continue
        match = recip_block.match(line)
        if match:
            # Recipient blocks are not accepted
            continue

        match = recip_allow.match(line)
        if match:
            # Join pattern, action, and comment in proper order, ensuring action is lowercase
            match = ''.join(match.group(1)) + ',exempt,' + ''.join(match.group(2))
            my_list.append(match)

    my_list = remove_empty(my_list)
    output = get_sorted(my_list)

    return output


def content_convert(filters):
    content = re.compile(r'''
                         (?P<pattern>.+),
                         (?P<comment>.*),
                         (?P<action>Block|Quarantine|Tag|Whitelist|Off),          # Inbound action
                         (?:Block|Quarantine|Tag|Whitelist|Off|Encrypt|Redirect), # Outbound action
                         (?P<subject>[01]),
                         (?P<header>[01]),
                         (?P<body>[01])''',
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

    my_list = remove_empty(my_list)
    output = get_sorted(my_list)

    return output


def attach_convert(filters):
    return "This function not available"


def main():
    # Nope
    pass

if __name__ == "__main__":
    main()