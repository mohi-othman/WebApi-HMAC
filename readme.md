# SSO using HMAC tokens


This is a basic implementation of HMAC tokens for use in Single Sign On system using WebAPI, which formed the basis for a production version that I developed for a client. It contains an implementation that uses the Web.Config as a store for the allowed keys as an example. Endpoints can be secured by use of attributes.

`Tools.WebAPI.Security` contains the main logic of verifying the payload.

`Tools.WebAPI.Security.Server` contains the WebAPI implementation using attributes.