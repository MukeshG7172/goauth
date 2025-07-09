package utils

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
	"github.com/jackc/pgx/v5"
)
var DB *pgx.Conn

func ConnectDB (){
	err := godotenv.Load("../.env")
	if err!=nil {
		log.Fatal("Error Loading .env file")
	}

	connStr := os.Getenv("DATABASE_URL")
	if connStr=="" {
		log.Fatal("No DATABASE_URL found in .env")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5* time.Second)
	defer cancel()

	DB, err = pgx.Connect(ctx, connStr)
	if err!=nil {
		log.Fatalf("Unable to Connect to DB: %v", err)
	}

	fmt.Println("Connected to Database Successfully")
}
