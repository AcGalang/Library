# Library Management System
This project is an API designed to manage users, authors, books, and their associations. It provides endpoints for creating, updating, showing, and deleting records, with secure token-based authentication to ensure authorized access. The system is built using PHP, Slim Framework, and MySQL, and it leverages Firebase for token handling and revocation.

## Features
- User Management
- Author Management
- Book Management
- Book-Author Association

## Dependencies
- PHP 7.4 or higher
- Composer
- MySQL
- Slim Framework
- Firebase
- Git
- Node.js
- XAMPP

## Usage

### User Management

#### Create Users
**Endpoint:** `/user/register`  
**Method:** POST  
**Payload:**
```json
{
    "username": "your_username",
    "password": "your_password"
}
```

#### Authenticate Users
**Endpoint:** `/user/auth`  
**Method:** POST  
**Payload:**
```json
{
    "username": "your_username",
    "password": "your_password"
}
```

#### Show Users
**Endpoint:** `/user/show`  
**Method:** GET  
**Header:**
```json
{
    "Authorization": "your_token"
}
```

#### Update Users
**Endpoint:** `/user/update`  
**Method:** PUT  
**Header:**
```json
{
    "token": "your_token",
    "userid": "your_userid",
    "username": "your_new_username",
    "password": "your_new_password"
}
```

#### Delete Users
**Endpoint:** `/user/delete`  
**Method:** DELETE  
**Header:**
```json
{
    "token": "your_token",
    "userid": "your_userid"
}
```

### Author Management

#### Create Authors
**Endpoint:** `/author/register`  
**Method:** POST  
**Payload:**
```json
{
    "token": "your_token"
    "name": "author_name"
}
```

#### Show Authors
**Endpoint:** `/author/show`  
**Method:** GET  
**Header:**
```json
{
    "Authorization": "your_token"
}
```

#### Update Authors
**Endpoint:** `/author/update`  
**Method:** PUT  
**Header:**
```json
{
    "token": "your_token",
    "authorid": "author_id",
    "name": "new_author_name"
}
```

#### Delete Authors
**Endpoint:** `/author/delete`  
**Method:** DELETE  
**Header:**
```json
{
    "token": "your_token",
    "authorid": "author_id"
}
```

### Book Management

#### Create Books
**Endpoint:** `/book/register`  
**Method:** POST  
**Payload:**
```json
{
    "title": "book_title",
    "authorid": "author_id"
}
```

#### Show Books
**Endpoint:** `/book/show`  
**Method:** GET  
**Header:**
```json
{
    "Authorization": "your_token"
}
```

#### Update Books
**Endpoint:** `/book/update`  
**Method:** PUT  
**Header:**
```json
{
    "token": "your_token",
    "bookid": "book_id",
    "title": "new_book_title",
    "authorid": "author_id"
}
```

#### Delete Books
**Endpoint:** `/book/delete`  
**Method:** DELETE  
**Header:**
```json
{
    "token": "your_token",
    "bookid": "book_id"
}
```

### Book-Author Association

#### Associate Book with Author
**Endpoint:** `/book_authors/register`  
**Method:** POST  
**Payload:**
```json
{
    "token": "your_token",
    "bookid": "book_id",
    "authorid": "author_id"
}
```

#### Show Book-Author Associations
**Endpoint:** `/book_authors/show`  
**Method:** GET  
**Header:**
```json
{
    "Authorization": "your_token"
}
```

#### Update Book-Author Association
**Endpoint:** `/book_authors/update`  
**Method:** PUT  
**Header:**
```json
{
    "token": "your_token",
    "collection_id": "collection_id",
    "bookid": "book_id",
    "authorid": "author_id"
}
```

#### Remove Book-Author Association
**Endpoint:** `/book_author/delete`  
**Method:** DELETE  
**Header:**
```json
{
    "token": "your_token",
    "collection_id": "collection_id",
}
```

## Token Handling
Tokens are generated upon user authentication and must be included in the header of subsequent requests. Tokens are stored in tokens file and marked as used once they expire or are invalidated.

## Error Messages and Solutions
- **401 Unauthorized:** Invalid or expired token. Ensure the token is valid and not expired.
- **400 Bad Request:** Missing required fields in the payload. Ensure all required fields are provided.
- **404 Not Found:** Resource not found. Ensure the resource ID is correct.
- **500 Internal Server Error:** Database error. Check the database connection and query.

## Code Excerpt
```php
<?php
$app->post('/user/register', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $uname = $data->username;
    $pass = $data->password;
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("SELECT COUNT(*) FROM users WHERE username = :username");
        $stmt->bindParam(':username', $uname);
        $stmt->execute();
        $count = $stmt->fetchColumn();

        if ($count > 0) {
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Username already taken"))));
        } else {
            $sql = "INSERT INTO users (username, password) VALUES (:username, :password)";
            $stmt = $conn->prepare($sql);
            $hashedPassword = hash('sha256', $pass);
            $stmt->bindParam(':username', $uname);
            $stmt->bindParam(':password', $hashedPassword);
            $stmt->execute();
            $response->getBody()->write(json_encode(array("status" => "success", "data" => null)));
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});
```

## Author
Name: Ariane Chryssyl M. Galang
Email: agalang09172@student.dmmmsu.edu.ph
GitHub: AcGalang
