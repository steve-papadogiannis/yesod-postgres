{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TypeFamilies #-}
module Handler.Home where

import Import

getHomeR :: Handler Value
getHomeR = do
    allComments <- runDB getAllComments
    returnJson allComments

getAllComments :: DB [Entity Comment]
getAllComments = selectList [] [Asc CommentId]
