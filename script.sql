USE [DapperIdentityAndJwtDB]
GO
/****** Object:  Table [dbo].[IdentityLogin]    Script Date: 8.11.2020 18:39:11 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[IdentityLogin](
	[LoginProvider] [varchar](128) NOT NULL,
	[ProviderKey] [varchar](128) NOT NULL,
	[UserId] [int] NOT NULL,
	[Name] [varchar](256) NOT NULL,
 CONSTRAINT [PK_IdentityLogin] PRIMARY KEY CLUSTERED 
(
	[LoginProvider] ASC,
	[ProviderKey] ASC,
	[UserId] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[IdentityRole]    Script Date: 8.11.2020 18:39:11 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[IdentityRole](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[Name] [varchar](50) NOT NULL,
	[IsActive] [bit] NULL,
 CONSTRAINT [PK_IdentityRole] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[IdentityRoleClaim]    Script Date: 8.11.2020 18:39:11 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[IdentityRoleClaim](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[RoleId] [int] NOT NULL,
	[ClaimType] [varchar](256) NOT NULL,
	[ClaimValue] [varchar](256) NULL,
 CONSTRAINT [PK_IdentityRoleClaim] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[IdentityUser]    Script Date: 8.11.2020 18:39:11 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[IdentityUser](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[Username] [varchar](256) NULL,
	[Email] [varchar](256) NULL,
	[EmailConfirmed] [bit] NOT NULL,
	[PasswordHash] [varchar](max) NULL,
	[SecurityStamp] [varchar](38) NULL,
	[PhoneNumber] [varchar](50) NULL,
	[PhoneNumberConfirmed] [bit] NOT NULL,
	[TwoFactorEnabled] [bit] NOT NULL,
	[LockoutEnd] [datetime] NULL,
	[LockoutEnabled] [bit] NOT NULL,
	[AccessFailedCount] [int] NOT NULL,
 CONSTRAINT [PK_IdentityUser] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[IdentityUserClaim]    Script Date: 8.11.2020 18:39:11 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[IdentityUserClaim](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[UserId] [int] NOT NULL,
	[ClaimType] [varchar](256) NOT NULL,
	[ClaimValue] [varchar](256) NOT NULL,
 CONSTRAINT [PK_IdentityUserClaim] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[IdentityUserRole]    Script Date: 8.11.2020 18:39:11 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[IdentityUserRole](
	[UserId] [int] NOT NULL,
	[RoleId] [int] NOT NULL,
 CONSTRAINT [PK_IdentityUserRole] PRIMARY KEY CLUSTERED 
(
	[UserId] ASC,
	[RoleId] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
SET IDENTITY_INSERT [dbo].[IdentityUser] ON 

INSERT [dbo].[IdentityUser] ([Id], [Username], [Email], [EmailConfirmed], [PasswordHash], [SecurityStamp], [PhoneNumber], [PhoneNumberConfirmed], [TwoFactorEnabled], [LockoutEnd], [LockoutEnabled], [AccessFailedCount]) VALUES (1, N'admin', N'ADMIN@SITE.COM', 0, N'AQAAAAEAACcQAAAAEFEn2tVGle/SGGH6BeXJAx1nnqoMIALdW6TWKdKtgIDJvq5nFTO+mml9JEFU1DKQlQ==', N'OL23PITIEITLDWNYJWUP2M3GMPZWLJKE', NULL, 0, 0, NULL, 1, 0)
INSERT [dbo].[IdentityUser] ([Id], [Username], [Email], [EmailConfirmed], [PasswordHash], [SecurityStamp], [PhoneNumber], [PhoneNumberConfirmed], [TwoFactorEnabled], [LockoutEnd], [LockoutEnabled], [AccessFailedCount]) VALUES (2, N'Üye', N'UYE@SITE.COM', 0, N'AQAAAAEAACcQAAAAEP1E69xWRcNg6EYMrF8rKSF078axtN8doT9DrKSheFOpKgMlh4rgTkkWoc3VdnJI3A==', N'OCT2ODYEHZWCDD7KZSJA66OOVAWW7GT7', NULL, 0, 0, NULL, 1, 0)
INSERT [dbo].[IdentityUser] ([Id], [Username], [Email], [EmailConfirmed], [PasswordHash], [SecurityStamp], [PhoneNumber], [PhoneNumberConfirmed], [TwoFactorEnabled], [LockoutEnd], [LockoutEnabled], [AccessFailedCount]) VALUES (3, N'deneme', N'DENEME@SITE.COM', 0, N'AQAAAAEAACcQAAAAEDlslTCxREHFxY/ZtbKeliMJTmTPzcEdnnanLtwHDTENsxNyGEPyP4v0bxf7eDehLg==', N'G6WIDVYH7HMU3E2HVM5HMP457KHBEM2T', NULL, 0, 0, NULL, 1, 0)
INSERT [dbo].[IdentityUser] ([Id], [Username], [Email], [EmailConfirmed], [PasswordHash], [SecurityStamp], [PhoneNumber], [PhoneNumberConfirmed], [TwoFactorEnabled], [LockoutEnd], [LockoutEnabled], [AccessFailedCount]) VALUES (4, N'baba', N'BABA@BABA.COM', 0, N'AQAAAAEAACcQAAAAEHJTwEbscEWThvUFdStCwzKgKCLYYGgpMAAdc/E1r3sDileIDBI0I3ZPMI2bTJbarA==', N'JWBJQCAKNSEO7DWB4MN3NVCNGVU2TQRW', NULL, 0, 0, NULL, 1, 0)
SET IDENTITY_INSERT [dbo].[IdentityUser] OFF
GO
ALTER TABLE [dbo].[IdentityLogin]  WITH CHECK ADD  CONSTRAINT [FK_dbo.IdentityLogin_dbo.IdentityUser_UserId] FOREIGN KEY([UserId])
REFERENCES [dbo].[IdentityUser] ([Id])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[IdentityLogin] CHECK CONSTRAINT [FK_dbo.IdentityLogin_dbo.IdentityUser_UserId]
GO
ALTER TABLE [dbo].[IdentityRoleClaim]  WITH CHECK ADD  CONSTRAINT [FK_IdentityRoleClaim_IdentityRole] FOREIGN KEY([RoleId])
REFERENCES [dbo].[IdentityRole] ([Id])
ON UPDATE CASCADE
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[IdentityRoleClaim] CHECK CONSTRAINT [FK_IdentityRoleClaim_IdentityRole]
GO
ALTER TABLE [dbo].[IdentityUserClaim]  WITH CHECK ADD  CONSTRAINT [FK_IdentityUserClaim_IdentityUser] FOREIGN KEY([UserId])
REFERENCES [dbo].[IdentityUser] ([Id])
ON UPDATE CASCADE
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[IdentityUserClaim] CHECK CONSTRAINT [FK_IdentityUserClaim_IdentityUser]
GO
ALTER TABLE [dbo].[IdentityUserRole]  WITH CHECK ADD  CONSTRAINT [FK_IdentityUserRole_IdentityRole] FOREIGN KEY([RoleId])
REFERENCES [dbo].[IdentityRole] ([Id])
ON UPDATE CASCADE
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[IdentityUserRole] CHECK CONSTRAINT [FK_IdentityUserRole_IdentityRole]
GO
ALTER TABLE [dbo].[IdentityUserRole]  WITH CHECK ADD  CONSTRAINT [FK_IdentityUserRole_IdentityUser] FOREIGN KEY([UserId])
REFERENCES [dbo].[IdentityUser] ([Id])
ON UPDATE CASCADE
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[IdentityUserRole] CHECK CONSTRAINT [FK_IdentityUserRole_IdentityUser]
GO
