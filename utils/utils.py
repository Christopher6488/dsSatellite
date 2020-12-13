def check_class(target):
        if 'sr' in target:
            return 'sat'
        if 'group' in target:
            return 'sat'
        if 'dc' in target:
            return 'dc'

def calculate_vel(weight):
    #TODO
    return 10000