# CRCOB23-Exam

This project requires the environment, on which it is run, to have the "Zero-Knowledge Swiss Knife" and "petlib" libraries installed.

However, "petlib" is built-in to the installation of the "Zero-Knowledge Swiss Knife" library, so that is the only installation needed to be done.

Alternatively, the project can be run from a Docker container, the setup of which is described below.

## Run the project via Docker and VS Code

Assuming you have installed Docker on your computer this is how you run the code.

### MacOS
1. Clone the repository
2. Open Docker and keep it running
3. Open terminal in repository folder.
4. In terminal write "make build" (only necessary for the first run), then "make up".
    4a. If you do not have make installed, then alternatively: "docker-compose build" followed by "docker-compose up -d"
5. Open VS Code and click on small purple square in the bottom-left corner
6. In drop-down menu choose "Attach to running container" and choose the running docker container.
7. The source code files should now be visible and runnable.
8. Use the terminal to run a selected file with the "python3 [filename]" command.
9. When finished you can close the container by opening a terminal in the project folder and run "make down" (alt. "docker-compose down"), or you can stop running the container in the Docker UI


### Windows
1. Clone the repository
2. Open Docker and keep it running
3. Open terminal in repository folder.
4. In terminal write "docker-compose build" (only necessary for the first run) followed by "docker-compose up -d"
5. Open VS Code and click on small purple square in the bottom-left corner
6. In drop-down menu choose "Attach to running container" and choose the running docker container.
7. The source code files should now be visible and runnable.
8. Use the terminal to run a selected file with the "python3 [filename]" command.
8. When finished you can close the container by opening a terminal in the project folder and run "docker-compose down", or you can stop running the container in the Docker UI
