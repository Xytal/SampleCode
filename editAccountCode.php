<?php

    if(!empty($_POST))
    {
        // Make sure the user entered a valid E-Mail address
        if(!filter_var($_POST['email'], FILTER_VALIDATE_EMAIL))
        {
            die("Invalid E-Mail Address");
        }

        // If the user is changing their E-Mail address, we need to make sure that
        // the new value does not conflict with a value that is already in the system.
        if($_POST['email'] != $_SESSION['user']['email'])
        {
            // Define SQL query
            $query = "
                SELECT
                    1
                FROM users
                WHERE
                    email = :email
            ";

            // Define query parameter values
            $query_params = array(
                ':email' => $_POST['email']
            );

            try
            {
                // Execute the query
                $stmt = $db->prepare($query);
                $result = $stmt->execute($query_params);
            }
            catch(PDOException $ex)
            {
                // Note: remove before going to production
                die("Failed to run query: " . $ex->getMessage());
            }

            // Retrieve results (if any)
            $row = $stmt->fetch();
            if($row)
            {
                die("This E-Mail address is already in use");
            }
        }

        // If the user entered a new password, hash it and generate a fresh salt
        if(!empty($_POST['password']))
        {
            $salt = dechex(mt_rand(0, 2147483647)) . dechex(mt_rand(0, 2147483647));
            $password = hash('sha256', $_POST['password'] . $salt);
            for($round = 0; $round < 65536; $round++)
            {
                $password = hash('sha256', $password . $salt);
            }
        }
        else
        {
            // If the user did not enter a new password we will not update their old one.
            $password = null;
            $salt = null;
        }

        // Initial query parameter values
        $query_params = array(
            ':email' => $_POST['email'],
            ':firstName' => $_POST['firstName'],
            ':lastName' => $_POST['lastName'],
            ':user_id' => $_SESSION['user']['id'],
        );

        if($password !== null)
        {
            $query_params[':password'] = $password;
            $query_params[':salt'] = $salt;
        }

        $query = "
            UPDATE users
            SET
                email = :email,
                firstName = :firstName,
                lastName = :lastName
        ";

        if($password !== null)
        {
            $query .= "
                , password = :password
                , salt = :salt
            ";
        }

        $query .= "
            WHERE
                id = :user_id
        ";

        try
        {
            // Execute the query
            $stmt = $db->prepare($query);
            $result = $stmt->execute($query_params);
        }
        catch(PDOException $ex)
        {
            // Note: remove before going to production
            die("Failed to run query: " . $ex->getMessage());
        }

        // Update the session with the new email
        $_SESSION['user']['email'] = $_POST['email'];

        // Update the session with the new first/last name
        $_SESSION['user']['first_name'] = $_POST['firstName'];
        $_SESSION['user']['last_name'] = $_POST['lastName'];

        // This redirects the user back to the members-only page after they register
        header("Location: private.php");

        die("Redirecting to private.php");
    }
