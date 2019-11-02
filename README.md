# quiniela
This will be the repo for Puiniela project

[WIP]

The idea is to use Postgres as the db

For Testing, pstgres will exist in a Docker container so you need to initialice using this steps:
1. Create the Docker image (In root directory of this project)
    ´docker build -f db_testing/Dockerfile . -t db_testing_img´
2. Run that image
    ´docker run --net='host' --name db_testing_container -t db_testing_img´
3. Enter to the running container
    ´docker exec -it db_testing_img bash´
4. Create the quiniela-testing db
    ´createdb -U postgres testing-quiniela´

[WIP]
