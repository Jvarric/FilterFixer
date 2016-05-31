#!/usr/bin/env python3
# FilterFixer
# Author: Eric Gillett <egillett@barracuda.com>
# Version: 1.0.9
# TODO change flask to return/accept JSON
# TODO add input for serial number on flask

import re, datetime, json, inspect
from pymysql import connect


def deduplicate(filters):
    my_list = filters.splitlines()
    output, dupes, dupe_num = remove_dupes(my_list)
    return output, dupes, dupe_num


def remove_dupes(filters):
    # Get calling function name so we don't write to db twice
    caller = inspect.stack()[1][3]
    print(caller)
    new, dupes = set(), set()
    output, esg_content_list, esg_attach_list = [], [], []
    dupe_num = 0
    esg_content_dict, esg_attach_dict, ess_content_dict = dict(), dict(), dict()

    esg_content = re.compile(r'''
                            (?P<pattern>.+),
                            (?P<comment>.*),
                            (?P<action>Block|Quarantine|Tag|Whitelist|Off),
                            (?P<out_action>Block|Quarantine|Tag|Whitelist|Off
                            |Encrypt
                            |Redirect),
                            (?P<subject>[01]),
                            (?P<header>[01]),
                            (?P<body>[01])''', re.I | re.X)
    esg_attach = re.compile(r'''
                           (?P<pattern>.+),
                           (?P<comment>.*),
                           (?P<action>Block|Quarantine|Tag|Whitelist|Off),
                           (?P<out_action>Block|Quarantine|Tag|Whitelist|Off
                           |Encrypt|Redirect),
                           (?P<archive>[01])''', re.I | re.X)
    ess_content = re.compile(r'''
                            (?P<pattern>.+),
                            (?P<action>Block|Allow|Quarantine),
                            (?P<subject>[01]),
                            (?P<header>[01]),
                            (?P<body>[01]),
                            (?P<attach>[01]),
                            (?P<sender>[01]),
                            (?P<recip>[01])''', re.I | re.X)

    for line in filters:
        pattern = (line.split(',', maxsplit=1)[0])
        # Check if line is a content filter or attachment filter
        esg_content_filter = esg_content.match(line)
        esg_attach_filter = esg_attach.match(line)
        ess_content_filter = ess_content.match(line)

        if pattern == '':
            continue
        elif esg_content_filter:
            # Check if pattern has been checked at least once before
            if pattern in esg_content_dict:
                dupes.add(pattern)
                dupe_num += 1
                # Compare new subject flag, if enabled, set enabled
                if esg_content_filter.group('subject') == '1':
                    esg_content_dict[pattern][3] = '1'
                # Compare new header flag, if enabled, set enabled
                if esg_content_filter.group('header') == '1':
                    esg_content_dict[pattern][4] = '1'
                # Compare new body flag, if enabled, set enabled
                if esg_content_filter.group('body') == '1':
                    esg_content_dict[pattern][5] = '1'
            else:
                # If new pattern, add to dict
                esg_content_dict[pattern] = [esg_content_filter.group('comment'),
                                             esg_content_filter.group('action'),
                                             esg_content_filter.group('out_action'),
                                             esg_content_filter.group('subject'),
                                             esg_content_filter.group('header'),
                                             esg_content_filter.group('body')]
        elif esg_attach_filter:
            # Check if pattern has been checked at least once before
            if pattern in esg_attach_dict:
                dupes.add(pattern)
                dupe_num += 1
                # Compare new subject flag, if enabled, set enabled
                if esg_attach_filter.group('archive') == '1':
                    esg_attach_dict[pattern][3] = '1'
            else:
                # If new pattern, add to dict
                esg_attach_dict[pattern] = [esg_attach_filter.group('comment'),
                                            esg_attach_filter.group('action'),
                                            esg_attach_filter.group('out_action'),
                                            esg_attach_filter.group('archive')]
        elif ess_content_filter:
            # Check if pattern has been checked at least once before
            if pattern in ess_content_dict:
                dupes.add(pattern)
                dupe_num += 1
                # Compare new subject flag, if enabled, set enabled
                if ess_content_filter.group('subject') == '1':
                    ess_content_dict[pattern][1] = '1'
                # Compare new header flag, if enabled, set enabled
                if ess_content_filter.group('header') == '1':
                    ess_content_dict[pattern][2] = '1'
                # Compare new body flag, if enabled, set enabled
                if ess_content_filter.group('body') == '1':
                    ess_content_dict[pattern][3] = '1'
                # Compare new attachment flag, if enabled, set enabled
                if ess_content_filter.group('attach') == '1':
                    ess_content_dict[pattern][4] = '1'
                # Compare new sender flag, if enabled, set enabled
                if ess_content_filter.group('sender') == '1':
                    ess_content_dict[pattern][5] = '1'
                # Compare new recipient flag, if enabled, set enabled
                if ess_content_filter.group('recip') == '1':
                    ess_content_dict[pattern][6] = '1'
            else:
                # If new pattern, add to dict
                ess_content_dict[pattern] = [ess_content_filter.group('action'),
                                             ess_content_filter.group('subject'),
                                             ess_content_filter.group('header'),
                                             ess_content_filter.group('body'),
                                             ess_content_filter.group('attach'),
                                             ess_content_filter.group('sender'),
                                             ess_content_filter.group('recip')]
        elif pattern not in new:
            new.add(pattern)
            output.append(line)
        else:
            dupes.add(pattern)
            dupe_num += 1

    # Merge flags into string and convert dictonary to list
    for k, v in esg_content_dict.items():
        esg_content_dict[k] = ','.join(v)
    esg_content_list = ['{},{}'.format(k, v) for k, v in esg_content_dict.items()]
    for k, v in esg_attach_dict.items():
        esg_attach_dict[k] = ','.join(v)
    esg_attach_list = ['{},{}'.format(k, v) for k, v in esg_attach_dict.items()]
    for k, v in ess_content_dict.items():
        ess_content_dict[k] = ','.join(v)
    ess_content_list = ['{},{}'.format(k, v) for k, v in ess_content_dict.items()]
    # Add content and attachment lists in case each hist has entries
    output.extend(esg_content_list)
    output.extend(esg_attach_list)
    output.extend(ess_content_list)

    output = remove_empty(output)
    output = get_sorted(output)
    # Only write to db if called directly
    if caller == 'deduplicate':
        write_db('dedupe', filters, output.splitlines())
    if dupes == set():
        dupes = ['No duplicates found']
    return output, dupes, dupe_num


def remove_empty(my_list):
    clean_list = [x for x in my_list if x is not None]
    return clean_list


def get_sorted(my_list):
    # Only sort pattern before first comma
    my_list.sort(key=lambda x: x.split(',', maxsplit=1)[0])
    output = '\n'.join(my_list)
    if output == '':
        return 'No results. Go back and check for improper formatting'
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
                    (?:(?P<action>.+),)?            # Blocklist action
                    (?P<comment>.*)''', re.I | re.X)
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

            # Change tag or quarantine to block
            if (action == 'tag') or (action == 'quarantine'):
                action = 'block'

            # Join back into a single line matching BESS formatting
            match = ','.join(match.group('ip', 'netmask')) + ',' + action + \
                    ',' + ''.join(match.group('comment'))
            my_list.append(match)

    output, dupes, dupe_num = remove_dupes(my_list)
    write_db('ip', my_filters, output.splitlines())

    return output, dupes, dupe_num


def sender_convert(filters):
    sender_allow = re.compile(r'(?P<pattern>.+?),(?P<comment>.*)', re.I)
    sender_block = re.compile(r'(?P<pattern>.+?),(?P<comment>.*),'
                              r'(?P<action>block|quarantine|tag)', re.I)
    my_list = []

    my_filters = filters.splitlines()

    for line in my_filters:
        # Strip newline character
        line = line.rstrip()
        if line.lower() == 'email address/domain,comment' or \
           line.lower() == 'email address/domain,comment,action':
            continue
        match = sender_block.match(line)

        if match:
            # Convert action to string and drop case
            action = ''.join(match.group('action'))
            action = action.lower()

            # Change tag to quarantine
            if action == 'tag':
                action = 'quarantine'

            # Join back into a single line matching BESS formatting
            match = ''.join(match.group('pattern')) + ',' + action + ',' + \
                    ''.join(match.group('comment'))
            my_list.append(match)
        else:
            match = sender_allow.match(line)
            # Join back into a single line matching BESS formatting
            if not match:
                continue
            match = ''.join(match.group('pattern')) + ',exempt,' + \
                    ''.join(match.group('comment'))
            my_list.append(match)

    output, dupes, dupe_num = remove_dupes(my_list)
    write_db('sender', my_filters, output.splitlines())

    return output, dupes, dupe_num


def recip_convert(filters):
    recip_allow = re.compile(r'(?P<pattern>.+?),(?P<comment>.*)', re.I)
    recip_block = re.compile(r'(.+?),(.+),(.*)', re.I)
    my_list = []

    my_filters = filters.splitlines()

    for line in my_filters:
        if line.lower() == 'email address/domain,comment' or \
           line.lower() == 'email address/domain,action,comment':
            continue
        match = recip_block.match(line)
        if match:
            # Recipient blocks are not accepted
            continue

        match = recip_allow.match(line)
        if match:
            # Join pattern, action, and comment in proper order
            match = ''.join(match.group('pattern')) + ',exempt,' + \
                    ''.join(match.group('comment'))
            my_list.append(match)

    output, dupes, dupe_num = remove_dupes(my_list)
    write_db('recipient', my_filters, output.splitlines())

    return output, dupes, dupe_num


def content_convert(filters):
    content = re.compile(r'''
                        (?P<pattern>.+),
                        (?P<comment>.*),
                        (?P<action>Block|Quarantine|Tag|Whitelist|Off),
                        (?:Block|Quarantine|Tag|Whitelist|Off|Encrypt|Redirect),
                        (?P<subject>[01]),
                        (?P<header>[01]),
                        (?P<body>[01])''', re.I | re.X)
    my_list = []
    my_filters = filters.splitlines()

    for line in my_filters:
        # Strip newline character
        line = line.rstrip()
        match = content.match(line)

        if match:
            # Convert action to string and drop case
            action = ''.join(match.group('action'))
            action = action.lower()

            # Change action to BESS equivalent
            if action == 'tag':
                action = 'quarantine'
            elif action == 'whitelist':
                action = 'allow'
            elif action == 'off':
                # Filter not enabled for inbound and should be ignored
                break

            # Combine into single line
            match = ','.join(match.group('pattern', 'comment')) + ',' + \
                    action + ',' + \
                    ','.join(match.group('subject', 'header', 'body')) + \
                    ',0,0,0'
            my_list.append(match)

    output, dupes, dupe_num = remove_dupes(my_list)
    write_db('content', my_filters, output.splitlines())

    return output, dupes, dupe_num


def attach_convert(filters):
    attach = re.compile(r'''
                        (?P<pattern>.+),
                        (?P<comment>.*),
                        (?P<action>Block|Quarantine|Tag|Whitelist|Off),
                        (?:Block|Quarantine|Tag|Whitelist|Off|Encrypt|Redirect),
                        (?P<archive>[01])''', re.I | re.X)
    my_list = []
    my_filters = filters.splitlines()

    for line in my_filters:
        # Strip newline character
        line = line.rstrip()
        match = attach.match(line)

        if match:
            # Convert action to string and drop case
            action = ''.join(match.group('action'))
            action = action.lower()

            # Change action to BESS equivalent
            if action == 'tag':
                action = 'quarantine'
            elif action == 'whitelist':
                action = 'ignore'
            elif action == 'off':
                # Filter not enabled for inbound and should be ignored
                break

            # Combine into single line
            match = 'filename,' + ','.join(match.group('pattern', 'archive'))\
                    + ',' + action + ',' + ''.join(match.group('comment'))
            my_list.append(match)

    output, dupes, dupe_num = remove_dupes(my_list)
    write_db('attachment', my_filters, output.splitlines())

    return output, dupes, dupe_num


def write_db(filter_type, input_filter, output_filter):
    if output_filter == 'No results. Go back and check for improper formatting':
        return 0
    cur_time = datetime.datetime.utcnow()
    conn = connect(host='localhost', port=3306, user='', passwd='', db='')
    cur = conn.cursor()
    try:
        cur.execute('INSERT INTO stats(date, filter, input, output) VALUES (%s, %s, '
                    '%s, %s)',
                    (cur_time, filter_type, json.dumps(input_filter), json.dumps(output_filter)))
    except Exception as e:
        print(e)
    finally:
        cur.close()
    return 0


def main():
    pass


if __name__ == "__main__":
    main()
