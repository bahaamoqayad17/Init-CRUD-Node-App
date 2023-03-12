# Init-CRUD-Node-App

Here you can generate CRUD Nodejs application by running the file then you can enter Your Models

Run:
  npm install

Now go to The util/ApiFeatures

in filter() function
you will find this RegExp like a symbol or somthing

just replace it with this

queryStr = queryStr.replace(/\b(gte|gt|lte|lt)\b/g, (match) => "$"+match);

Now you should go to the .env File to setup your enviroment variables

- DataBase Connection String
- DataBase Password
- JWT Secret Key
- etc....

Go to Models Folders and setup your database schema in the models you have entered

Then you are good to go with your application and build it your own way

If you like to enter other Models after running the file already
You can run it again and it will automaticly add the new models that you added

I can accept any updates and optimization to improve this library
