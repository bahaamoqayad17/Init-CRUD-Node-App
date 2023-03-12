# Init-CRUD-Node-App

Here you can generate CRUD Nodejs application by running the file then you can enter Your Models

RUN : npm install

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

Then a little help you can use if you like 

You can find DatabaseSeeder file in Seeder Folder
You can find there a json file for every model 
You can add json objects that you can start with for testing

After adding the data 
RUN : npm run fresh

This library Provides Error Handling and its a Global Middleware

Like if you want to send an error 
You can use The AppError Class i have built 
Just send the error in the next function like this :

return next(new AppError("This is Not Found Error",404))

And there is CatchAsync Function 
The use of it is to escape the try catch block every time you use async await function
All You should do is wrap the async function with the CatchAsync
And the error will be handled

Last You can take a look at the ErrorHandler file in the Controllers folder
And you will see all the already handled errors in development and production

Then you are good to go with your application and build it your own way

For Development
RUN : npm start

For Production
RUN : npm run prod

If you like to enter other Models after running the file already
You can run it again and it will automaticly add the new models that you added

I can accept any updates and optimization to improve this library
