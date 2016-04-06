import re

REGEX = re.compile(r'(?:(.+?),(.*),(.+))')


def main():
    with open('filters.txt') as my_file:
        filters = my_file.readlines()

    for line in filters:
        print(line, end="")
        line = line.rstrip()
        match = REGEX.match(line)

        if match:
            print("The matches are: {}".format(match.groups()))
            print("The re-ordered filter is: {}\n".format(','.join(match.group(1, 3, 2))))

#if __name__ == "__main()__":
main()
