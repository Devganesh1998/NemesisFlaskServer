from instance.credentials import awspass, awsendpoint, dbname

SQLALCHEMY_DATABASE_URI = 'mysql://root:'+ awspass +'@' + awsendpoint +'/' + dbname
