# Pasty

Pasty is a wrapper which makes working with Paseto tokens as simple as
possible. [Paseto](https://github.com/paragonie/paseto) (Platform-Agnostic SEcurity TOkens) is a specification for
secure stateless tokens.

Unlike JSON Web Tokens (JWT), which gives developers more than enough rope with which to hang themselves, Paseto only
allows secure operations. JWT gives you "algorithm agility", while Paseto gives you "versioned protocols." It's 
unlikely that you'll be able to use Paseto insecurely.

This module uses [go-paseto](https://github.com/aidantwoods/go-paseto) to generate and validate tokens. 