# Football Playground Booking System

The football playground booking system is a web application designed to facilitate the booking of football playgrounds for matches and events. It allows users to browse available playgrounds, schedule matches, and manage bookings.

## Feature
- User Registration and Authentication: Users can register, log in, and log out.
- Browse Playgrounds: Users can view a list of available football playgrounds.
- Booking Management: Users can book playgrounds for specific times and dates, view their bookings, and cancel if necessary.
- Admin Interface: Admins can manage playground details, view all bookings, and handle user management.

## Tech Stack
- Frontend: HTML, CSS, JavaScript
- Backend: Golang
- Database: JSON
- Authentication: JWT (JSON Web Token)

## Installation
1. Clone the repository:
```
git clone https://github.com/yourusername/football-playground-booking.git
cd football-playground-booking
```
2. Install dependencies:
```
go mod tidy
 ```
3. Set up environment variables:
Create a .env file in the root directory and add the following:
```
JWT_SECRET=YOUR_SECRET
EMAIL=YOUR_EMAIL
EMAIL_PASSWORD=YOUR_PASSWORD
```
4. Run the application:
```
 go run main.go
```
## Usage
- Register an account: Navigate to the registration page and create a new account.
- Login: Use your credentials to log in.
- Browse Playgrounds: View available playgrounds and their details.
- Book a Playground: Select a playground, choose a date and time, and confirm your booking.


