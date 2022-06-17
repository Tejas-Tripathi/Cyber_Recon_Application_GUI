import instaloader
bot = instaloader.Instaloader()
Username = 'spectareeeeeeeeeeeeeeeeeeeee'
try:
  bot.download_profile(Username, profile_pic_only = True)
  profile = instaloader.Profile.from_username(bot.context, Username)
  print(profile)
  posts = profile.get_posts()
  print(posts)
except:
  print("profile not found")
  


# l1=[]
# try:
#   for index, post in enumerate(posts, 1):
#     bot.download_post(post, target=f"{profile.username}")
    
# except:
#   exit()