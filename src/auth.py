import os


class ApiKey:
    def __init__(self):
        self.__api_key = ''

    @property
    def api_key(self):
        with open('config/.api_key', 'r') as file:
            self.__api_key = file.readline().strip()

        return self.__api_key

    @api_key.setter
    def api_key(self, auth_key):
        if os.path.exists('config/.api_key'):
            self.save_key('config/.api_key', auth_key)
            print('config/.api_key has been successfully updated')
        else:
            self.save_key('config/.api_key', auth_key)
            print('config/.api_key has been successfully created')

        self.__api_key = auth_key

    def save_key(self, path, auth_key):
        with open(path, 'w') as file:
            file.write(auth_key)
            file.close()

