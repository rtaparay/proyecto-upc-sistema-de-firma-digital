# Install with Docker Compose

Run the following command to start the application:

```
docker compose up --build
```

# Set up for development

First install Play framework 1.8.0 as described in https://github.com/playframework/play1?tab=readme-ov-file#getting-started

* TODO check if Visual Studio Code is supported

Then prepare the project for the preferred IDE with one of the following commands:

```
play eclipsify
play idealize
play netbeansify
```

And finally start the project:

```
play run
```
