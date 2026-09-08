// Common breached and dictionary passwords list for offline lookup
// Sourced from top entries of SecLists / RockYou most frequent passwords
const commonPasswords = new Set([
  '123456', 'password', '123456789', '12345678', '12345', '111111', '1234567',
  'sunshine', 'qwerty', 'iloveyou', 'princess', 'admin', 'welcome', '666666',
  'football', '123123', 'monkey', 'charlie', 'donald', 'dragon', 'baseball',
  'pass', 'access', 'master', 'shadow', 'ashley', 'bailey', 'superman', 'michael',
  'jessica', 'secret', 'hunter', 'jordan', 'starwars', 'harley', 'password1',
  'trustno1', 'killer', 'orange', 'bullet', 'silver', 'freedom', 'cheese',
  'batman', 'ginger', 'buster', 'robert', 'thomas', 'soccer', 'hockey', 'playboy',
  'pepper', 'killer', 'bubbles', 'barbie', 'blessed', 'chelsea', 'anthony',
  'family', 'summer', 'winter', 'autumn', 'spring', 'love', 'honey', 'cookie',
  'system', 'yellow', 'computer', 'monkey1', 'dragon1', 'guitar', 'flower',
  'purple', 'angel', 'diamond', 'matrix', 'tigers', 'cougar', 'patriots',
  'cowboys', 'steelers', 'packers', 'yankees', 'redsox', 'lakers', 'chicago',
  'london', 'paris', 'tokyo', 'newyork', 'california', 'florida', 'america',
  'hacker', 'test', 'tester', 'guest', 'root', 'user', 'default', 'oracle',
  'cisco', 'letmein', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234321', '000000',
  '654321', '987654321', '987654', '112233', '121212', 'abc123', 'qazwsx',
  'passw0rd', 'p@ssw0rd', 'p@ssword', 'p@ssw0rd1', 'admin123', 'admin@123',
  'root123', 'root@123', 'welcome1', 'welcome123', 'welcome@123', 'temp123',
  'changeme', 'testing', 'login', 'portal', 'secure', 'security', 'database'
]);

module.exports = { commonPasswords };
