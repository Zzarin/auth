package handlers

import (
	"context"
	"log"
	"net"
	"os"
	"strings"
	"time"

	sq "github.com/Masterminds/squirrel"
	rpc "github.com/Zzarin/auth/pkg/user_v1"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	userTable               = "users"
	tableID                 = "id"
	tableName               = "name"
	tablePasswordHash       = "password_hash"
	tablePeasswordConfirmed = "password_confirmed"
	tableEmail              = "email"
	tableRole               = "role"
	tableCreatedAt          = "created_at"
	tableUpdatedAt          = "updated_at"
)

var dbTimeOutDefault = time.Duration(5 * time.Second)

type UserHandler struct {
	done   chan os.Signal
	dbConn *pgxpool.Pool

	rpc.UnimplementedUserV1Server
}

func NewUserHandler(conn *pgxpool.Pool) *UserHandler {
	return &UserHandler{
		done:   make(chan os.Signal),
		dbConn: conn,
	}
}

func (u *UserHandler) ListenAndServe(ctx context.Context, address string) error {
	serverOptions := []grpc.ServerOption{
		// grpc.UnaryInterceptor(), // add interceptor later
		// grpc.StreamInterceptor(), // add interceptor later
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:              30 * time.Second, // Time between pings
			Timeout:           5 * time.Second,  // Timeout for connection to be considered dead
			MaxConnectionIdle: 40 * time.Second, // If a client is idle for 40 seconds, send a GOAWAY
		}),

		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second, // Minimum time between pings
			PermitWithoutStream: true,             // Allow pings even if no active streams
		}),
	}

	s := grpc.NewServer(serverOptions...)
	reflection.Register(s)
	rpc.RegisterUserV1Server(s, u)

	lis, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}

	log.Printf("listening for connections on %s", address)

	go func() {
		if err = s.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			log.Fatal(err)
		}
	}()

	<-ctx.Done()
	s.GracefulStop()
	log.Println("stopped listening for clients...", ctx.Err())
	return nil
}

func (u *UserHandler) Stop() {
	u.done <- os.Interrupt
}

type UserCreateRequest struct {
	PersonalInfo      User
	PasswordHash      string
	PasswordConfirmed string
}

func convertCreateRequestToUser(rpcUser *rpc.User, passwordConfirmed string, passwordHash string) UserCreateRequest {
	return UserCreateRequest{
		PersonalInfo: User{
			Name:  rpcUser.GetName(),
			Email: rpcUser.GetEmail(),
			Role:  strings.ToLower(rpcUser.GetRole().String()),
		},
		PasswordHash:      passwordHash,
		PasswordConfirmed: passwordConfirmed,
	}
}

func (u *UserHandler) Create(ctx context.Context, req *rpc.CreateRequest) (*rpc.CreateResponse, error) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.GetAuthParameters().Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "password is in wrong format")
	}

	user := convertCreateRequestToUser(req.GetUser(), req.GetAuthParameters().GetPasswordConfirmed(), string(passwordHash))

	builderInsert := sq.Insert(userTable).
		PlaceholderFormat(sq.Dollar).
		Columns(tableName, tablePasswordHash, tablePeasswordConfirmed, tableEmail, tableRole).
		Values(user.PersonalInfo.Name, passwordHash, user.PasswordConfirmed, user.PersonalInfo.Email, user.PersonalInfo.Role).
		Suffix("RETURNING id")

	query, args, err := builderInsert.ToSql()
	if err != nil {
		log.Printf("user: %v, %v", user, errors.Wrap(err, "ToSql"))
		return nil, status.Error(codes.Internal, "preparing query")
	}

	ctxDB, cancel := context.WithTimeout(ctx, dbTimeOutDefault)
	defer cancel()

	var userID int64
	err = u.dbConn.QueryRow(ctxDB, query, args...).Scan(&userID)
	if err != nil {
		log.Printf("user: %v, %v", user, errors.Wrap(err, "QueryRow"))
		return nil, status.Error(codes.Internal, "writing in db")
	}

	return &rpc.CreateResponse{UserId: userID}, nil
}

type UserGetResponse struct {
	User      User
	CreatedAt *time.Time
	UpdatedAt *time.Time
}

type User struct {
	ID    int64
	Name  string
	Email string
	Role  string
}

func (u *UserHandler) Get(ctx context.Context, req *rpc.GetRequest) (*rpc.GetResponse, error) {
	builderInsert := sq.Select(tableID, tableName, tableEmail, tableRole, tableCreatedAt, tableUpdatedAt).
		PlaceholderFormat(sq.Dollar).
		From(userTable).
		Where(sq.Eq{tableID: req.GetUserId()})

	query, args, err := builderInsert.ToSql()
	if err != nil {
		log.Printf("user_id: %v, %v", req.GetUserId(), errors.Wrap(err, "ToSql"))
		return nil, status.Error(codes.Internal, "preparing query")
	}

	ctxDB, cancel := context.WithTimeout(ctx, dbTimeOutDefault)
	defer cancel()

	row := u.dbConn.QueryRow(ctxDB, query, args...)
	userResponse, err := convertRowToUser(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, status.Error(codes.NotFound, "no records found")
		}

		log.Printf("user_id: %v, %v", req.GetUserId(), errors.Wrap(err, "getUserFromRow"))
		return nil, status.Error(codes.Internal, "get from db")
	}

	return &rpc.GetResponse{
		UserInfo: &rpc.UserInfo{
			Id: userResponse.User.ID,
			User: &rpc.User{
				Name:  userResponse.User.Name,
				Email: userResponse.User.Email,
				Role:  stringToUserRole(userResponse.User.Role),
			},
			CreatedAt: timestamppb.New(*userResponse.CreatedAt),
			UpdatedAt: getTimeOrNil(userResponse.UpdatedAt),
		},
	}, nil
}

func convertRequestToUser(rpcUser *rpc.User, userID int64) User {
	return User{
		ID:    userID,
		Name:  rpcUser.GetName(),
		Email: rpcUser.GetEmail(),
		Role:  strings.ToLower(rpcUser.GetRole().String()),
	}
}

func (u *UserHandler) Update(ctx context.Context, req *rpc.UpdateRequest) (*emptypb.Empty, error) {
	user := convertRequestToUser(req.GetUser(), req.GetUserId())

	builderInsert := sq.Update(userTable).
		PlaceholderFormat(sq.Dollar).
		Set(tableName, user.Name).Set(tableEmail, user.Email).Set(tableRole, user.Role).
		Where(sq.Eq{tableID: req.GetUserId()})

	query, args, err := builderInsert.ToSql()
	if err != nil {
		log.Printf("user: %v, %v", user, errors.Wrap(err, "ToSql"))
		return nil, status.Error(codes.Internal, "preparing query")
	}

	ctxDB, cancel := context.WithTimeout(ctx, dbTimeOutDefault)
	defer cancel()

	tag, err := u.dbConn.Exec(ctxDB, query, args...)
	if err != nil {
		log.Printf("user: %v, %v", user, errors.Wrap(err, "Exec"))
		return nil, status.Error(codes.Internal, "writing in db")
	}

	if tag.RowsAffected() == 0 {
		return nil, status.Error(codes.NotFound, "record not found")
	}

	return &emptypb.Empty{}, nil
}

func (u *UserHandler) Delete(ctx context.Context, req *rpc.DeleteRequest) (*emptypb.Empty, error) {
	builderDelete := sq.Delete(userTable).
		PlaceholderFormat(sq.Dollar).
		Where(sq.Eq{tableID: req.GetUserId()})

	query, args, err := builderDelete.ToSql()
	if err != nil {
		log.Printf("user_id: %v, %v", req.GetUserId(), errors.Wrap(err, "ToSql"))
		return nil, status.Error(codes.Internal, "preparing query")
	}

	ctxDB, cancel := context.WithTimeout(ctx, dbTimeOutDefault)
	defer cancel()

	tag, err := u.dbConn.Exec(ctxDB, query, args...)
	if err != nil {
		log.Printf("user_id: %v, %v", req.GetUserId(), errors.Wrap(err, "Exec"))
		return nil, status.Error(codes.Internal, "executing query")
	}

	if tag.RowsAffected() == 0 {
		return nil, status.Error(codes.NotFound, "record not found")
	}

	return &emptypb.Empty{}, nil
}

func convertRowToUser(row pgx.Row) (*UserGetResponse, error) {
	var userResponse UserGetResponse
	if err := row.Scan(
		&userResponse.User.ID,
		&userResponse.User.Name,
		&userResponse.User.Email,
		&userResponse.User.Role,
		&userResponse.CreatedAt,
		&userResponse.UpdatedAt,
	); err != nil {
		if err == pgx.ErrNoRows {
			return nil, err
		}
		return nil, errors.Wrap(err, "error row.Scan")
	}

	return &userResponse, nil
}

func stringToUserRole(role string) rpc.UserRole {
	switch role {
	case "user":
		return rpc.UserRole_USER
	case "admin":
		return rpc.UserRole_ADMIN
	default:
		return rpc.UserRole_UNKNOWN
	}
}

func getTimeOrNil(inputTime *time.Time) *timestamppb.Timestamp {
	if inputTime == nil {
		return nil
	}
	return timestamppb.New(*inputTime)
}
