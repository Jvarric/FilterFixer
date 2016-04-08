import sys
import re

REGEX = re.compile(r'(.+?),(.*),(.+)')


def ip():
    pass


def combineSender(input):
    sender_allow = re.compile(r'(.+?),(.*)', re.I)
    sender_block = re.compile(r'(.+?),(.*),(block|quarantine|tag)', re.I)
    out = []

    for line in input:
        line = line.rstrip()
        try:
            match = sender_block.match(line)
            if match:
                # print("block - {}".format(match.groups()))
                # Join pattern, action, and comment in proper order, ensuring action is lowercase
                action = ''.join(match.group(3))
                action = action.lower()

                # If action was tag, change to quarantine
                if action == "tag":
                    action = "quarantine"

                # Reorder line to match BESS formatting
                match = ''.join(match.group(1)) + "," + action + "," + ''.join(match.group(2))
            else:
                match = sender_allow.match(line)
                # print("allow - {}".format(match.groups()))
                match = ''.join(match.group(1)) + ",exempt," + ''.join(match.group(2))
        except:
            e = sys.exc_info()
            print("Not a sender filter. Check formatting. Error: {}".format(e))

        # Save newly formatted line
        out.append(match)

    return out


def recipient():
    pass


def attachment():
    pass


def content():
    pass


def main():
    with open('sender_filters.txt') as my_file:
        filters = my_file.readlines()

    output = combineSender(filters)

    print(output)
'''
    for line in filters:
        print(line, end="")
        line = line.rstrip()
        match = REGEX.match(line)

        if match:
            print("The matches are: {}".format(match.groups()))
            print("The re-ordered filter is: {}\n".format(', '.join(match.group(0, 1, 2, 3)) + ",blah"))
'''
#if __name__ == "__main()__":
main()
