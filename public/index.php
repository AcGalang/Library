<?php
use \Psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

/*
Activity Requirements: 
must registered first then auth log in, token(to CRUD books and author) then new token will be shown for next use
(firebase authentication for revocation)
put tokens on array 
*/

require '../src/vendor/autoload.php';
$config = ['settings' => ['displayErrorDetails' => true]];
$app = new Slim\App($config);
function isValidToken($token) {
    $key = 'server_hack';

    try {
        $decoded = JWT::decode($token, new Key($key, 'HS256'));

        if ($decoded->exp < time()) {
            return false; 
        }

        return $decoded;

    } catch (Exception $e) {
        return false;
    }
}

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

$app->post('/user/auth', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $uname = $data->username;
    $pass = $data->password;
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";
    $token_file = 'C:\xampp\htdocs\library\logs\tokens.txt'; 

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "SELECT * FROM users WHERE username='" . $uname . "' 
                AND password='" . hash('SHA256', $pass) . "'";

        $stmt = $conn->prepare($sql);
        $stmt->execute();
        $stmt->setFetchMode(PDO::FETCH_ASSOC);
        $data = $stmt->fetchAll(); // ARRAY data returned

        $issuedAt = time();
        $expirationTime = $issuedAt + 600; // Token expires in 10 minutes (600 seconds)

        // Business logic
        if (count($data) == 1) {
            $key = 'server_hack'; // Your secret key
            $iat = time();
            $payload = [
                'iss' => 'http://library.org',  // Issuer
                'aud' => 'http://library.com',  // Audience
                'iat' => $iat,                  // Issued at
                'exp' => $iat + 600,            // Expiration time (10 minutes)
                "data" => array(
                    "userid" => $data[0]['userid'] // Add user ID or relevant data
                )
            ];

            
            $jwt = JWT::encode($payload, $key, 'HS256');

            // Store the issued token in the text file
            file_put_contents($token_file, "Token: $jwt issued at: " . date('Y-m-d H:i:s', $issuedAt) . PHP_EOL, FILE_APPEND);

        
            $response->getBody()->write(json_encode(array(
                "status" => "success",
                "token" => $jwt,
                "data" => null
            )));
        } else {
            $response->getBody()->write(json_encode(array(
                "status" => "fail",
                "data" => array("title" => "Authentication Failed")
            )));
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array(
            "status" => "fail",
            "data" => array("title" => $e->getMessage())
        )));
    }

    $conn = null;
    return $response;
});

$app->get('/user/show', function (Request $request, Response $response) {
    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";
    $token_file = 'C:\xampp\htdocs\library\logs\tokens.txt'; 
    $key = 'server_hack'; 

    $authHeader = $request->getHeader('Authorization');
    if (!$authHeader || empty($authHeader[0])) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "message" => "No token provided")));
    }

    $token = str_replace('Bearer ', '', $authHeader[0]);

    try {
        $decoded = JWT::decode($token, new Key($key, 'HS256'));

        file_put_contents($token_file, "Used Token: $token at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);

        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("SELECT userid, username FROM users");
        $stmt->execute();
        $users = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if ($users) {
            $issuedAt = time();
            $expirationTime = $issuedAt + 600; 

            $payload = [
                "iss" => "http://library.org",
                "aud" => "http://library.com",
                "iat" => $issuedAt,
                "exp" => $expirationTime,
                "data" => [
                    "transaction" => "user_show",
                ]
            ];

            $newToken = JWT::encode($payload, $key, 'HS256');

            return $response->write(json_encode(array(
                "status" => "success",
                "data" => $users,
                "new_token" => $newToken,
            )));
        } else {
            return $response->write(json_encode(array("status" => "fail", "message" => "No users found")));
        }
    } catch (Exception $e) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "message" => "Invalid or expired token")));
    }

    $conn = null;
});

$app->put('/user/update', function (Request $request, Response $response) {
    $data = json_decode($request->getBody(), true);
    $token_file = 'C:\xampp\htdocs\library\logs\tokens.txt'; 
    $key = 'server_hack'; 

    if (empty($data['userid']) || empty($data['token']) || (!isset($data['username']) && !isset($data['password']))) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "message" => "userid, token, and at least one of username or password are required")));
    }

    $token = $data['token'];

    try {
        $decoded = JWT::decode($token, new Key($key, 'HS256'));
    } catch (Exception $e) {
        file_put_contents($token_file, "Expired/Invalid Token: $token at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);

        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "message" => "Unauthorized or expired token")));
    }

    $userId = $data['userid'];
    $newUsername = $data['username'] ?? null;
    $newPassword = isset($data['password']) ? hash('sha256', $data['password']) : null;

    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("SELECT * FROM users WHERE userid = :userid");
        $stmt->bindParam(':userid', $userId);
        $stmt->execute();
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            return $response->withStatus(404)->write(json_encode(array("status" => "fail", "message" => "User not found")));
        }

        $updateRequired = false;
        if ($newUsername && $newUsername != $user['username']) {
            $updateRequired = true;
        }
        if ($newPassword && $newPassword != $user['password']) {
            $updateRequired = true;
        }

        if (!$updateRequired) {
            return $response->write(json_encode(array("status" => "success", "message" => "No changes were made")));
        }

        // Update user in the database
        $sql = "UPDATE users SET ";
        $fieldsToUpdate = [];
        if ($newUsername) {
            $fieldsToUpdate[] = "username = :username";
        }
        if ($newPassword) {
            $fieldsToUpdate[] = "password = :password";
        }
        $sql .= implode(", ", $fieldsToUpdate);
        $sql .= " WHERE userid = :userid";

        $stmt = $conn->prepare($sql);
        if ($newUsername) {
            $stmt->bindParam(':username', $newUsername);
        }
        if ($newPassword) {
            $stmt->bindParam(':password', $newPassword);
        }
        $stmt->bindParam(':userid', $userId);
        $stmt->execute();


        file_put_contents($token_file, "Used Token: $token at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);

        $issuedAt = time();
        $expirationTime = $issuedAt + 600; // New token expires in 1 hour

        $newPayload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $issuedAt,
            'exp' => $expirationTime,
            "data" => array(
                "userid" => $userId
            )
        ];

        $newToken = JWT::encode($newPayload, $key, 'HS256');

        return $response->write(json_encode(array(
            "status" => "success",
            "message" => "User updated successfully",
            "new_token" => $newToken,
        )));

    } catch (PDOException $e) {
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "message" => "Database error occurred: " . $e->getMessage())));
    }

    $conn = null;
});

$app->delete('/user/delete', function (Request $request, Response $response) {
    $data = json_decode($request->getBody(), true);
    $token_file = 'C:\xampp\htdocs\library\logs\tokens.txt'; 
    $key = 'server_hack';

    if (empty($data['token'])) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "message" => "Token is required")));
    }
    
    if (empty($data['userid'])) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "message" => "userid is required")));
    }

    $token = $data['token'];


    try {
        $decoded = JWT::decode($token, new Key($key, 'HS256'));
    } catch (Exception $e) {
        file_put_contents($token_file, "Expired/Invalid Token: $token at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "message" => "Unauthorized or expired token")));
    }

    $userId = $data['userid'];

    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("SELECT userid FROM users WHERE userid = :userid");
        $stmt->bindParam(':userid', $userId);
        $stmt->execute();
        $existingUser = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$existingUser) {
            return $response->withStatus(404)->write(json_encode(array("status" => "fail", "message" => "User not found")));
        }

        $stmt = $conn->prepare("DELETE FROM users WHERE userid = :userid");
        $stmt->bindParam(':userid', $userId);
        $stmt->execute();

        file_put_contents($token_file, "Used Token: $token at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);

        $issuedAt = time();
        $expirationTime = $issuedAt + 600; 

        $newPayload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $issuedAt,
            'exp' => $expirationTime,
            "data" => array(
                "userid" => $userId
            )
        ];

        $newToken = JWT::encode($newPayload, $key, 'HS256');

        return $response->write(json_encode(array(
            "status" => "success",
            "message" => "User deleted successfully",
            "new_token" => $newToken,
        )));
    } catch (PDOException $e) {
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "message" => "Database error occurred: " . $e->getMessage())));
    }

    $conn = null;
});

$app->post('/author/register', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $authorname = $data->name ?? null; 
    $token = $data->token ?? null;

    $token_file = 'C:\xampp\htdocs\library\logs\tokens.txt'; 
    $key = 'server_hack'; 

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $decoded = isValidToken($token);
        if (!$decoded) {
            file_put_contents($token_file, "Expired/Invalid Token: $token at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);
            return $response->withStatus(401)->write(json_encode(array("status" => "fail", "message" => "Unauthorized")));
        }

        if (!isset($decoded->data->userid)) {
            return $response->withStatus(401)->write(json_encode(array("status" => "fail", "message" => "Invalid token structure")));
        }

        $userId = $decoded->data->userid;

        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("SELECT COUNT(*) FROM authors WHERE name = :name");
        $stmt->bindParam(':name', $authorname);
        $stmt->execute();
        $count = $stmt->fetchColumn();

        if ($count > 0) {
            return $response->withStatus(400)->write(json_encode(array("status" => "fail", "message" => "Author already recorded")));
        }

        $sql = "INSERT INTO authors (name) VALUES (:name)";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':name', $authorname);
        $stmt->execute();

        file_put_contents($token_file, "Used Token: $token at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);


        $iat = time();
        $exp = $iat + 600; 
        $newPayload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat,
            'exp' => $exp,
            "data" => array(
                "userid" => $userId
            )
        ];
        $newToken = JWT::encode($newPayload, $key, 'HS256');

        return $response->write(json_encode(array(
            "status" => "success",
            "message" => "Author registered",
            "new_token" => $newToken,
        )));
    } catch (Exception $e) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }
});

$app->get('/author/show', function (Request $request, Response $response) {
    
    $authHeader = $request->getHeader('Authorization');
    $token = isset($authHeader[0]) ? str_replace('Bearer ', '', $authHeader[0]) : null;

    
    $token_file = 'C:\xampp\htdocs\library\logs\tokens.txt';

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";
    $key = 'server_hack';

    try {
        
        if (empty($token)) {
            return $response->withStatus(400)->write(json_encode(array("status" => "fail", "message" => "Token is required")));
        }

        
        $decoded = isValidToken($token);
        if (!$decoded) {
            file_put_contents($token_file, "Expired/Invalid Token: $token at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);
            return $response->withStatus(401)->write(json_encode(array("status" => "fail", "message" => "Unauthorized")));
        }

        $iat = time();
        $exp = $iat + 600; 
        $newPayload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat,
            'exp' => $exp,
            "data" => array(
                "userid" => $decoded->data->userid
            )
        ];
        $newToken = JWT::encode($newPayload, $key, 'HS256');

        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("SELECT authorid, name FROM authors");
        $stmt->execute();
        $authors = $stmt->fetchAll(PDO::FETCH_ASSOC);

        file_put_contents($token_file, "Used Token: $token at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);

        $response->getBody()->write(json_encode(array(
            "status" => "success",
            "data" => $authors,
            "new_token" => $newToken, 
        )));
    } catch (PDOException $e) {
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "message" => "Database error: " . $e->getMessage())));
    }

    $conn = null;
    return $response->withHeader('Content-Type', 'application/json');
});

$app->put('/author/update', function (Request $request, Response $response) {
    
    $data = json_decode($request->getBody(), true);
    $authorId = $data['authorid'];
    $name = $data['name'];
    $token = $data['token'] ?? $request->getHeaderLine('Authorization'); 

    if (strpos($token, 'Bearer ') === 0) {
        $token = substr($token, 7);
    }

    $token_file = 'C:\xampp\htdocs\library\logs\tokens.txt'; 
    $key = 'server_hack'; 

    if (empty($token) || !isValidToken($token)) {
        file_put_contents($token_file, "Expired/Invalid Token: $token at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "message" => "Unauthorized")));
    }

    $decoded = isValidToken($token);

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("SELECT * FROM authors WHERE authorid = :authorid");
        $stmt->bindParam(':authorid', $authorId);
        $stmt->execute();
        $author = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$author) {
            return $response->withStatus(404)->write(json_encode(array("status" => "fail", "message" => "Author not found")));
        }

        $sql = "UPDATE authors SET name = :name WHERE authorid = :authorid";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':name', $name);
        $stmt->bindParam(':authorid', $authorId);
        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            file_put_contents($token_file, "Used Token: $token at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);

            $iat = time();
            $exp = $iat + 600; 
            $newPayload = [
                'iss' => 'http://library.org',
                'aud' => 'http://library.com',
                'iat' => $iat,
                'exp' => $exp,
                "data" => array("userid" => $decoded->data->userid) 
            ];
            $newToken = JWT::encode($newPayload, $key, 'HS256');

            return $response->write(json_encode(array("status" => "success", "message" => "Author updated successfully", "new_token" => $newToken)));
        } else {
            return $response->getBody()->write(json_encode(array("status" => "fail", "message" => "No changes made")));
        }
    } catch (PDOException $e) {
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "message" => "Database error: " . $e->getMessage())));
    }

    $conn = null; 
    return $response->withHeader('Content-Type', 'application/json');
});

$app->delete('/author/delete', function (Request $request, Response $response) {
    $data = json_decode($request->getBody(), true);

    if (empty($data['authorid']) || empty($data['token'])) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "message" => "authorid and token are required")));
    }

    $token_file = 'C:\xampp\htdocs\library\logs\tokens.txt'; 
    $decoded = isValidToken($data['token']);
    if (!$decoded) {
        file_put_contents($token_file, "Expired/Invalid Token: " . $data['token'] . " at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "message" => "Unauthorized")));
    }

    $authorId = $data['authorid'];
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("DELETE FROM authors WHERE authorid = :authorid");
        $stmt->bindParam(':authorid', $authorId);
        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            file_put_contents($token_file, "Used Token: " . $data['token'] . " at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);

            $iat = time();
            $exp = $iat + 600; 
            $newPayload = [
                'iss' => 'http://library.org',
                'aud' => 'http://library.com',
                'iat' => $iat,
                'exp' => $exp,
                "data" => array(
                    "userid" => $decoded->data->userid
                )
            ];
            $newToken = JWT::encode($newPayload, 'server_hack', 'HS256');

            return $response->write(json_encode(array(
                "status" => "success",
                "message" => "Author deleted successfully",
                "new_token" => $newToken,
            )));
        } else {
            return $response->withStatus(404)->write(json_encode(array("status" => "fail", "message" => "No author found for authorid: " . $authorId)));
        }
    } catch (PDOException $e) {
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }
});

$app->post('/book/register', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody(), true);
    $title = $data['title'];
    $authorid = $data['authorid'];
    $token = $data['token'];
    
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    $key = 'server_hack'; 

    try {
        $decoded = JWT::decode($token, new Key($key, 'HS256'));
        $userId = $decoded->data->userid;
        
        if ($decoded->exp < time()) {
            return $response->withStatus(401)->write(json_encode(array("status" => "fail", "message" => "Token expired")));
        }

        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("SELECT COUNT(*) FROM books WHERE title = :title");
        $stmt->bindParam(':title', $title);
        $stmt->execute();
        $count = $stmt->fetchColumn();

        if ($count > 0) {
            return $response->withStatus(400)->write(json_encode(array("status" => "fail", "message" => "Book already exists")));
        }

        $sql = "INSERT INTO books (title, authorid) VALUES (:title, :authorid)";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':title', $title);
        $stmt->bindParam(':authorid', $authorid);
        $stmt->execute();

        $iat = time();
        $exp = $iat + 600; 
        $newPayload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat,
            'exp' => $exp,
            "data" => array(
                "userid" => $userId
            )
        ];
        $newToken = JWT::encode($newPayload, $key, 'HS256');

        return $response->write(json_encode(array("status" => "success", "message" => "Book registered successfully", "new_token" => $newToken)));

    } catch (Exception $e) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }
});

$app->get('/book/show', function (Request $request, Response $response) {
    $token = $request->getHeaderLine('Authorization'); 

    if (strpos($token, 'Bearer ') === 0) {
        $token = substr($token, 7);
    }

    $token_file = 'C:\xampp\htdocs\library\logs\tokens.txt'; 

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";
    $key = 'server_hack'; 

    try {
        if (empty($token)) {
            return $response->withStatus(400)->write(json_encode(array("status" => "fail", "message" => "Token is required")));
        }

        $decoded = isValidToken($token);
        if (!$decoded) {
            file_put_contents($token_file, "Expired/Invalid Token: $token at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);
            return $response->withStatus(401)->write(json_encode(array("status" => "fail", "message" => "Unauthorized")));
        }

        $iat = time();
        $exp = $iat + 600; 
        $newPayload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat,
            'exp' => $exp,
            "data" => array(
                "userid" => $decoded->data->userid
            )
        ];
        $newToken = JWT::encode($newPayload, $key, 'HS256');

        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("SELECT books.bookid, books.title, authors.name AS author FROM books 
                                JOIN authors ON books.authorid = authors.authorid");
        $stmt->execute();
        $books = $stmt->fetchAll(PDO::FETCH_ASSOC);

        file_put_contents($token_file, "Used Token: $token at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);

        $response->getBody()->write(json_encode(array(
            "status" => "success",
            "data" => $books,
            "new_token" => $newToken, 
        )));
    } catch (PDOException $e) {
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "message" => "Database error: " . $e->getMessage())));
    }

    return $response->withHeader('Content-Type', 'application/json');
});

$app->get('/book/{bookid}', function (Request $request, Response $response, array $args) {
    $bookId = $args['bookid'];
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    $token_file = 'C:\xampp\htdocs\library\logs\tokens.txt'; 
    $key = 'server_hack'; 

    $token = $request->getHeaderLine('Authorization');

    if (strpos($token, 'Bearer ') === 0) {
        $token = substr($token, 7);
    }

    try {
        if (empty($token)) {
            return $response->withStatus(400)->write(json_encode(array("status" => "fail", "message" => "Token is required")));
        }

        $decoded = isValidToken($token);
        if (!$decoded) {
            file_put_contents($token_file, "Expired/Invalid Token: $token at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);
            return $response->withStatus(401)->write(json_encode(array("status" => "fail", "message" => "Unauthorized")));
        }

        $iat = time();
        $exp = $iat + 600;
        $newPayload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat,
            'exp' => $exp,
            "data" => array(
                "userid" => $decoded->data->userid
            )
        ];
        $newToken = JWT::encode($newPayload, $key, 'HS256');

        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("SELECT books.bookid, books.title, authors.name AS author FROM books 
                                JOIN authors ON books.authorid = authors.authorid 
                                WHERE books.bookid = :bookid");
        $stmt->bindParam(':bookid', $bookId);
        $stmt->execute();
        $book = $stmt->fetch(PDO::FETCH_ASSOC);

        file_put_contents($token_file, "Used Token: $token at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);

        if ($book) {
            $response->getBody()->write(json_encode(array(
                "status" => "success",
                "data" => $book,
                "new_token" => $newToken, 
            )));
        } else {
            $response->getBody()->write(json_encode(array("status" => "fail", "message" => "Book not found")));
        }
    } catch (PDOException $e) {
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "message" => "Database error: " . $e->getMessage())));
    }

    $conn = null; 
    return $response->withHeader('Content-Type', 'application/json');
});

$app->put('/book/update', function (Request $request, Response $response) {

    $data = json_decode($request->getBody(), true);
    $bookId = $data['bookid'];
    $title = $data['title'];
    $authorId = $data['authorid'];
    $token = $data['token'] ?? $request->getHeaderLine('Authorization'); 

    if (strpos($token, 'Bearer ') === 0) {
        $token = substr($token, 7);
    }

    $token_file = 'C:\xampp\htdocs\library\logs\tokens.txt'; 
    $key = 'server_hack'; 

    if (empty($token) || !isValidToken($token)) {
        file_put_contents($token_file, "Expired/Invalid Token: $token at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "message" => "Unauthorized")));
    }

    $decoded = isValidToken($token);

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("SELECT * FROM books WHERE bookid = :bookid");
        $stmt->bindParam(':bookid', $bookId);
        $stmt->execute();
        $book = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$book) {
            return $response->withStatus(404)->write(json_encode(array("status" => "fail", "message" => "Book not found")));
        }

        $sql = "UPDATE books SET title = :title, authorid = :authorid WHERE bookid = :bookid";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':title', $title);
        $stmt->bindParam(':authorid', $authorId);
        $stmt->bindParam(':bookid', $bookId);
        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            file_put_contents($token_file, "Used Token: $token at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);

            $iat = time();
            $exp = $iat + 600; 
            $newPayload = [
                'iss' => 'http://library.org',
                'aud' => 'http://library.com',
                'iat' => $iat,
                'exp' => $exp,
                "data" => array("userid" => $decoded->data->userid)
            ];
            $newToken = JWT::encode($newPayload, $key, 'HS256');

            return $response->write(json_encode(array("status" => "success", "message" => "Book updated successfully", "new_token" => $newToken)));
        } else {
            return $response->getBody()->write(json_encode(array("status" => "fail", "message" => "No changes made")));
        }
    } catch (PDOException $e) {
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "message" => "Database error: " . $e->getMessage())));
    }

    $conn = null; 
    return $response->withHeader('Content-Type', 'application/json');
});

$app->delete('/book/delete', function (Request $request, Response $response) {
    $data = json_decode($request->getBody(), true);
    $bookId = $data['bookid'];
    $token = $data['token'] ?? $request->getHeaderLine('Authorization'); 

    if (strpos($token, 'Bearer ') === 0) {
        $token = substr($token, 7);
    }

    $token_file = 'C:\xampp\htdocs\library\logs\tokens.txt'; 
    $key = 'server_hack'; 

    if (empty($token) || !isValidToken($token)) {
        file_put_contents($token_file, "Expired/Invalid Token: $token at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "message" => "Unauthorized")));
    }

    $decoded = isValidToken($token);

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("SELECT * FROM books WHERE bookid = :bookid");
        $stmt->bindParam(':bookid', $bookId);
        $stmt->execute();
        $book = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$book) {
            return $response->withStatus(404)->write(json_encode(array("status" => "fail", "message" => "Book not found")));
        }

        $stmt = $conn->prepare("DELETE FROM books WHERE bookid = :bookid");
        $stmt->bindParam(':bookid', $bookId);
        $stmt->execute();

        file_put_contents($token_file, "Used Token: $token at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);

        $iat = time();
        $exp = $iat + 600; 
        $newPayload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat,
            'exp' => $exp,
            "data" => array("userid" => $decoded->data->userid) 
        ];
        $newToken = JWT::encode($newPayload, $key, 'HS256');

        return $response->write(json_encode(array("status" => "success", "message" => "Book deleted successfully", "new_token" => $newToken)));
    } catch (PDOException $e) {
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "message" => "Database error: " . $e->getMessage())));
    }

    $conn = null; 
    return $response->withHeader('Content-Type', 'application/json');
});

$app->post('/book_authors/register', function (Request $request, Response $response) {
    
    $data = json_decode($request->getBody(), true);
    $bookId = $data['bookid'];
    $authorId = $data['authorid'];
    $token = $data['token'] ?? $request->getHeaderLine('Authorization'); 

    if (strpos($token, 'Bearer ') === 0) {
        $token = substr($token, 7);
    }

    $token_file = 'C:\xampp\htdocs\library\logs\tokens.txt'; 
    $key = 'server_hack'; 

    if (empty($token) || !isValidToken($token)) {
        file_put_contents($token_file, "Expired/Invalid Token: $token at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "message" => "Unauthorized")));
    }

    $decoded = isValidToken($token);

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $bookCheck = $conn->prepare("SELECT * FROM books WHERE bookid = :bookid");
        $bookCheck->bindParam(':bookid', $bookId);
        $bookCheck->execute();

        if (!$bookCheck->fetch(PDO::FETCH_ASSOC)) {
            return $response->withStatus(404)->write(json_encode(array("status" => "fail", "message" => "Book not found")));
        }

        $authorCheck = $conn->prepare("SELECT * FROM authors WHERE authorid = :authorid");
        $authorCheck->bindParam(':authorid', $authorId);
        $authorCheck->execute();

        if (!$authorCheck->fetch(PDO::FETCH_ASSOC)) {
            return $response->withStatus(404)->write(json_encode(array("status" => "fail", "message" => "Author not found")));
        }

        $sql = "INSERT INTO book_authors (bookid, authorid) VALUES (:bookid, :authorid)";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':bookid', $bookId);
        $stmt->bindParam(':authorid', $authorId);
        $stmt->execute();

        file_put_contents($token_file, "Used Token: $token at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);

        $iat = time();
        $exp = $iat + 600; 
        $newPayload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat,
            'exp' => $exp,
            "data" => array("userid" => $decoded->data->userid)
        ];
        $newToken = JWT::encode($newPayload, $key, 'HS256');

        $response->getBody()->write(json_encode(array("status" => "success", "message" => "Book-Author relationship registered successfully", "new_token" => $newToken)));
    } catch (PDOException $e) {
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "message" => "Database error: " . $e->getMessage())));
    }

    $conn = null; 
    return $response->withHeader('Content-Type', 'application/json');
});

$app->get('/book_authors/show', function (Request $request, Response $response) {

    $authHeader = $request->getHeader('Authorization');
    if (!$authHeader || empty($authHeader[0])) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "message" => "No token provided")));
    }

    $token = str_replace('Bearer ', '', $authHeader[0]);

    $token_file = 'C:\xampp\htdocs\library\logs\tokens.txt'; 

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";
    $key = 'server_hack'; 

    try {
        if (empty($token)) {
            return $response->withStatus(400)->write(json_encode(array("status" => "fail", "message" => "Token is required")));
        }

        $decoded = isValidToken($token);
        if (!$decoded) {
            file_put_contents($token_file, "Expired/Invalid Token: $token at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);
            return $response->withStatus(401)->write(json_encode(array("status" => "fail", "message" => "Unauthorized")));
        }

        $iat = time();
        $exp = $iat + 600;
        $newPayload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat,
            'exp' => $exp,
            "data" => array(
                "userid" => $decoded->data->userid
            )
        ];
        $newToken = JWT::encode($newPayload, $key, 'HS256');

        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("SELECT book_authors.collection_id, book_authors.bookid, book_authors.authorid, 
                                        books.title, authors.name AS author 
                                 FROM book_authors 
                                 JOIN books ON book_authors.bookid = books.bookid 
                                 JOIN authors ON book_authors.authorid = authors.authorid");
        $stmt->execute();
        $bookAuthors = $stmt->fetchAll(PDO::FETCH_ASSOC);

        file_put_contents($token_file, "Used Token: $token at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);

        $response->getBody()->write(json_encode(array(
            "status" => "success",
            "data" => $bookAuthors,
            "new_token" => $newToken,
        )));
    } catch (PDOException $e) {
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "message" => "Database error: " . $e->getMessage())));
    }

    $conn = null; 
    return $response->withHeader('Content-Type', 'application/json');
});

$app->put('/book_authors/update', function (Request $request, Response $response) {
    $data = json_decode($request->getBody(), true);
    $collectionId = $data['collection_id'];
    $bookId = $data['bookid'] ?? null;
    $authorId = $data['authorid'] ?? null;
    $token = $data['token'] ?? null; 

    $token_file = 'C:\xampp\htdocs\library\logs\tokens.txt'; 

    if (empty($collectionId) || (empty($bookId) && empty($authorId))) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "message" => "collection_id and at least one of bookid or authorid are required")));
    }

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";
    $key = 'server_hack'; 

    try {
        if (empty($token)) {
            return $response->withStatus(400)->write(json_encode(array("status" => "fail", "message" => "Token is required")));
        }

        $decoded = isValidToken($token);
        if (!$decoded) {
            file_put_contents($token_file, "Expired/Invalid Token: $token at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);
            return $response->withStatus(401)->write(json_encode(array("status" => "fail", "message" => "Unauthorized")));
        }

        file_put_contents($token_file, "Used Token: $token at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);

        $iat = time();
        $exp = $iat + 600; 
        $newPayload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat,
            'exp' => $exp,
            "data" => array(
                "userid" => $decoded->data->userid 
            )
        ];
        $newToken = JWT::encode($newPayload, $key, 'HS256');

        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("SELECT * FROM book_authors WHERE collection_id = :collection_id");
        $stmt->bindParam(':collection_id', $collectionId);
        $stmt->execute();
        $existing = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$existing) {
            return $response->withStatus(404)->write(json_encode(array("status" => "fail", "message" => "Book-Author relationship not found")));
        }

        $sql = "UPDATE book_authors SET ";
        $fieldsToUpdate = [];
        if ($bookId) {
            $fieldsToUpdate[] = "bookid = :bookid";
        }
        if ($authorId) {
            $fieldsToUpdate[] = "authorid = :authorid";
        }
        $sql .= implode(", ", $fieldsToUpdate);
        $sql .= " WHERE collection_id = :collection_id";

        $stmt = $conn->prepare($sql);
        if ($bookId) {
            $stmt->bindParam(':bookid', $bookId);
        }
        if ($authorId) {
            $stmt->bindParam(':authorid', $authorId);
        }
        $stmt->bindParam(':collection_id', $collectionId);
        $stmt->execute();

        return $response->write(json_encode(array(
            "status" => "success",
            "message" => "Book-Author relationship updated successfully",
            "new_token" => $newToken, 
        )));

    } catch (PDOException $e) {
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "message" => "Database error: " . $e->getMessage())));
    }

    $conn = null; 
});

$app->delete('/book_authors/delete', function (Request $request, Response $response) {
    $data = json_decode($request->getBody(), true);
    $collectionId = $data['collection_id'];
    $token = $data['token'] ?? null;

    $token_file = 'C:\xampp\htdocs\library\logs\tokens.txt'; 

    if (empty($collectionId)) {
        return $response->withStatus(400)->write(json_encode(array("status" => "fail", "message" => "collection_id is required")));
    }

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";
    $key = 'server_hack'; 

    try {
        if (empty($token)) {
            return $response->withStatus(400)->write(json_encode(array("status" => "fail", "message" => "Token is required")));
        }

        $decoded = isValidToken($token); 
        if (!$decoded) {
            file_put_contents($token_file, "Expired/Invalid Token: $token at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);
            return $response->withStatus(401)->write(json_encode(array("status" => "fail", "message" => "Unauthorized")));
        }

        file_put_contents($token_file, "Used Token: $token at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);

        $iat = time();
        $exp = $iat + 600; 
        $newPayload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat,
            'exp' => $exp,
            "data" => array(
                "userid" => $decoded->data->userid
            )
        ];
        $newToken = JWT::encode($newPayload, $key, 'HS256');

        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("DELETE FROM book_authors WHERE collection_id = :collection_id");
        $stmt->bindParam(':collection_id', $collectionId);
        $stmt->execute();

        return $response->write(json_encode(array(
            "status" => "success",
            "message" => "Book-Author relationship deleted successfully",
            "new_token" => $newToken, 
        )));
    } catch (PDOException $e) {
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    $conn = null; 
});

$app->run();
?>
